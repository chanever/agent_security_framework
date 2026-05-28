# benign-skill-extended

확장 정상 Claude skills corpus (anthropics/skills에서 추출한 10개).
benign-skills와 동일한 agent 흐름 — skill 표본만 크다.

```json
{
  "family": "benign-skill-extended",
  "task": "Inspect this Claude skill — open SKILL.md to see what it does.",
  "action_reason": "Read the skill's instructions before applying it.",
  "history": [
    {
      "step": 0,
      "action": {"type": "command", "command": "ls", "reason": "list skill files"},
      "stdout": "SKILL.md  (and other skill files)",
      "exit_code": 0
    }
  ]
}
```
