#!/usr/bin/env python3
"""Aggregate the two MalPacDetector RF CSV reports into a chanever-shaped
JSON (same schema as bench/run_clawvet_bench.py output)."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def metrics(c: dict) -> dict:
    TP, FP, TN, FN = c.get('TP', 0), c.get('FP', 0), c.get('TN', 0), c.get('FN', 0)
    n = TP + FP + TN + FN
    P = TP / (TP + FP) if (TP + FP) else 0
    R = TP / (TP + FN) if (TP + FN) else 0
    return {
        'n': n,
        'TP': TP, 'FP': FP, 'TN': TN, 'FN': FN,
        'dsr': R,
        'specificity': TN / (TN + FP) if (TN + FP) else 0,
        'precision': P,
        'accuracy': (TP + TN) / n if n else 0,
        'f1': 2 * P * R / (P + R) if (P + R) else 0,
    }


def read_predictions(csv_path: Path, label: str) -> list[dict]:
    family = 'malicious-npm' if label == 'mal' else 'benign-npm'
    rows: list[dict] = []
    with csv_path.open() as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        for row in reader:
            case = row['package name'].strip()
            pred = row['predict'].strip()
            decision = 'block' if pred == 'malicious' else 'allow'
            if label == 'mal':
                outcome = 'TP' if decision == 'block' else 'FN'
            else:
                outcome = 'FP' if decision == 'block' else 'TN'
            rows.append({
                'family': family,
                'label': 'malicious' if label == 'mal' else 'benign',
                'case': case,
                'name': case.rsplit('-', 1)[0] if '-' in case else case,
                'classifier': 'random_forest',
                'predict': pred,
                'decision': decision,
                'outcome': outcome,
            })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--mal-csv', required=True)
    parser.add_argument('--ben-csv', required=True)
    parser.add_argument('--out',     required=True)
    args = parser.parse_args()

    rows = read_predictions(Path(args.mal_csv), 'mal') \
         + read_predictions(Path(args.ben_csv), 'ben')

    conf: Counter = Counter()
    per_family: dict[str, Counter] = {
        'malicious-npm': Counter(), 'benign-npm': Counter(),
    }
    for r in rows:
        conf[r['outcome']] += 1
        per_family[r['family']][r['outcome']] += 1

    out = {
        'framework': 'MalPacDetector (CGCL-codes/MalPacDetector-core, IEEE TIFS 2025)',
        'classifier': 'RandomForest (trained on MalnpmDB by paper authors)',
        'corpus': 'chanever bench npm: malicious-npm + benign-npm',
        'source_csvs': {'mal': args.mal_csv, 'ben': args.ben_csv},
        'confusion_total': dict(conf),
        'confusion_per_family': {k: dict(v) for k, v in per_family.items()},
        'metrics': metrics(conf),
        'rows': rows,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))
    print(f'wrote {args.out}: {dict(conf)}')


if __name__ == '__main__':
    main()
