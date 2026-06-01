"""Safeguard adapter for the vulnerable CLI agent."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from security_framework.analysis.reputation_analyzer import analyze_reputation
from security_framework.analysis.static_analyzer import analyze_static
from security_framework.classification.asset_kind_classifier import classify_asset_kind, skipped_result as skipped_asset_kind
from security_framework.classification.external_target_extractor import extract_external_targets
from security_framework.classification.trigger import classify_command
from security_framework.config import SecurityFrameworkConfig
from security_framework.evidence.evidence_builder import build_evidence_package, write_evidence_package
from security_framework.sandbox.sandbox_runner import run_in_sandbox
from security_framework.sandbox.trace_parser import parse_trace
from security_framework.verifier import verify


class ShadowSandboxSafeguard:
    """Inspect command actions with trigger, shadow execution, evidence, and verification."""

    def __init__(self, config: SecurityFrameworkConfig | None = None) -> None:
        self.config = (config or SecurityFrameworkConfig.from_env()).resolve_paths()

    def inspect(self, action: dict, context: dict) -> dict:
        if not self.config.enabled:
            return {"decision": "allow", "action": action, "reason": "security framework disabled"}

        if action.get("type") == "stop":
            return {"decision": "allow", "action": action, "reason": "stop action allowed"}

        if action.get("type") != "command":
            return self._block(action, "Unknown or unsupported action type.", context=context)

        command = action.get("command", "")
        classification = classify_command(command, context)

        if not classification.get("external_env"):
            run_dir = self._run_dir(context)
            external_analysis = self._external_interaction_analysis(action, context, classification)
            evidence_package = build_evidence_package(context.get("task", ""), context, action, classification, None, None, external_analysis)
            verifier_result = verify(evidence_package, self.config)
            evidence_path = write_evidence_package(evidence_package, run_dir / "evidence_package.json")
            self._write_json(run_dir / "verifier_result.json", verifier_result)
            return self._map_decision(verifier_result, action, evidence_path, run_dir, classification, "Local command verified.")

        run_dir = self._run_dir(context)
        external_analysis = self._external_interaction_analysis(action, context, classification)

        if not classification.get("needs_shadow_execution"):
            evidence_package = build_evidence_package(context.get("task", ""), context, action, classification, None, None, external_analysis)
            verifier_result = verify(evidence_package, self.config)
            evidence_path = write_evidence_package(evidence_package, run_dir / "evidence_package.json")
            self._write_json(run_dir / "verifier_result.json", verifier_result)
            return self._map_decision(verifier_result, action, evidence_path, run_dir, classification)

        if not self.config.shadow_sandbox_enabled:
            return self._block(action, "Shadow sandbox is required but disabled.", classification=classification, context=context)

        sandbox_result = run_in_sandbox(command, context.get("cwd", "."), run_dir, self.config)
        semantic_trace = parse_trace(sandbox_result.get("trace_raw", ""))
        evidence_package = build_evidence_package(context.get("task", ""), context, action, classification, sandbox_result, semantic_trace, external_analysis)
        verifier_result = verify(evidence_package, self.config)
        evidence_path = write_evidence_package(evidence_package, run_dir / "evidence_package.json")
        self._write_json(run_dir / "sandbox_result.json", self._redact_docker_command(sandbox_result))
        self._write_json(run_dir / "semantic_trace.json", semantic_trace)
        self._write_json(run_dir / "verifier_result.json", verifier_result)

        return self._map_decision(verifier_result, action, evidence_path, run_dir, classification)

    def _external_interaction_analysis(self, action: dict, context: dict, classification: dict) -> dict:
        targets = []
        asset_kind = skipped_asset_kind()
        static_result = {"status": "skipped", "findings": [], "summary": "No analysis was requested."}
        reputation_result = {"status": "skipped", "signals": [], "summary": "No analysis was requested."}

        if classification.get("external_env"):
            targets = classification.get("targets") or extract_external_targets(action, context, classification)
            asset_kind = classify_asset_kind(action, context, classification, targets, self.config)
            if asset_kind.get("status") == "completed":
                if self.config.static_analysis_enabled:
                    static_result = analyze_static(action, context, targets, classification, asset_kind)
                if self.config.reputation_analysis_enabled:
                    reputation_result = analyze_reputation(action, context, targets, classification, asset_kind)
            else:
                static_result = {"status": "skipped", "findings": [], "summary": "Asset kind was not confidently classified."}
                reputation_result = {"status": "skipped", "signals": [], "summary": "Asset kind was not confidently classified."}

        return {
            "targets": targets,
            "asset_kind": asset_kind,
            "static_analysis": static_result,
            "reputation_analysis": reputation_result,
        }

    def _map_decision(self, verifier_result: dict, original_action: dict, evidence_path: str, run_dir: Path, classification: dict, prefix: str = "") -> dict:
        decision = verifier_result.get("decision", "HOLD")
        reason = verifier_result.get("reason", "No verifier reason.")
        if prefix:
            reason = f"{prefix} {reason}"
        common = {
            "classification": classification,
            "verifier_result": verifier_result,
            "evidence_package_path": evidence_path,
            "artifact_dir": str(run_dir),
        }
        if decision == "ALLOW":
            return {"decision": "allow", "action": original_action, "reason": reason, **common}
        if decision == "ALLOW_WITH_SANITIZATION":
            return {"decision": "block", "action": self._stop_action("Sanitization required."), "reason": "Sanitization required before real execution.", **common}
        if decision == "ISOLATE":
            return {"decision": "block", "action": self._stop_action(reason), "reason": f"Sandbox-only recommended: {reason}", **common}
        return {"decision": "block", "action": self._stop_action(reason), "reason": reason, **common}

    def _block(
        self,
        action: dict,
        reason: str,
        classification: dict | None = None,
        context: dict | None = None,
        verifier_result: dict | None = None,
        evidence_path: str | None = None,
        run_dir: Path | None = None,
    ) -> dict:
        result = {
            "decision": "block",
            "action": self._stop_action(reason),
            "reason": reason,
            "classification": classification or classify_command(action.get("command", ""), context),
            "verifier_result": verifier_result,
        }
        if evidence_path:
            result["evidence_package_path"] = evidence_path
        if run_dir:
            result["artifact_dir"] = str(run_dir)
        return result

    def _run_dir(self, context: dict) -> Path:
        run_id = context.get("run_id") or "run"
        step = context.get("step", 0)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = Path(self.config.artifact_root) / f"{run_id}_step{step}_{stamp}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _stop_action(answer: str) -> dict:
        return {"type": "stop", "answer": answer, "reason": "security framework decision"}

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _redact_docker_command(result: dict) -> dict:
        copied = dict(result)
        copied["docker_command"] = "[redacted command array; see sandbox configuration]"
        return copied
