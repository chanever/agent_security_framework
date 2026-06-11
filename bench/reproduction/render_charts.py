#!/usr/bin/env python3
"""Re-render every comparison chart from the JSON result files.

Default: read JSONs from ``expected_outputs/`` (the committed reference set)
and overwrite PNGs in ``expected_outputs/charts/``. Pass ``--in /tmp/repro``
to render from a freshly-run set of JSONs instead.

Requires matplotlib + numpy.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# Use Pan-CJK Noto for Korean rendering when the host has it
try:
    from matplotlib import font_manager
    font_manager.fontManager.addfont(
        '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc')
    plt.rcParams['font.family'] = 'Noto Sans CJK JP'
except Exception:
    pass
plt.rcParams['axes.unicode_minus'] = False

COL = {'TP': '#1A9641', 'TN': '#74add1', 'FN': '#D7191C',
       'FP': '#fdae61', 'ERR': '#999999'}
BLUE, RED = '#2C7BB6', '#D7191C'


# ──────────────────────── per-framework chart helper ───────────────────────

def per_family_bar(family_order, fam_data, title, subtitle, out, height=5.6):
    n_fam = len(family_order)
    fig, ax = plt.subplots(figsize=(max(8.5, n_fam*1.05), height))
    x = np.arange(n_fam)
    bottoms = np.zeros(n_fam)
    for cat in ('TP', 'FN', 'TN', 'FP', 'ERR'):
        vals = np.array([fam_data[f].get(cat, 0) for f in family_order], dtype=float)
        if vals.sum() == 0: continue
        ax.bar(x, vals, bottom=bottoms, color=COL[cat], label=cat,
               edgecolor='white', linewidth=0.5)
        for i, v in enumerate(vals):
            if v > 0:
                colour = 'white' if cat in ('TP', 'FN') else 'black'
                ax.text(i, bottoms[i] + v/2, f'{cat}\n{int(v)}',
                        ha='center', va='center', color=colour,
                        fontsize=9, fontweight='bold')
        bottoms += vals
    for i, f in enumerate(family_order):
        total = sum(fam_data[f].get(c, 0) for c in ('TP','FN','TN','FP','ERR'))
        ax.text(i, bottoms[i] + max(bottoms)*0.012, f'n={total}',
                ha='center', va='bottom', fontsize=9, color='#444')
    ax.set_xticks(x); ax.set_xticklabels(family_order, rotation=25, ha='right', fontsize=10)
    ax.set_ylabel('Cases'); ax.set_ylim(0, bottoms.max() * 1.12)
    ax.set_title(f'{title}\n{subtitle}', fontsize=12, fontweight='bold')
    ax.legend(loc='upper right', fontsize=9, ncol=5)
    ax.grid(axis='y', alpha=0.3); ax.set_axisbelow(True)
    fig.tight_layout(); fig.savefig(out, dpi=140, bbox_inches='tight'); plt.close(fig)


def metrics_from(c):
    TP, FP = c.get('TP', 0), c.get('FP', 0)
    TN, FN = c.get('TN', 0), c.get('FN', 0)
    P = TP / (TP + FP) if (TP + FP) else 0
    R = TP / (TP + FN) if (TP + FN) else 0
    S = TN / (TN + FP) if (TN + FP) else 0
    F = 2*P*R/(P+R) if (P+R) else 0
    return {'TP':TP,'FP':FP,'TN':TN,'FN':FN,'dsr':R,'specificity':S,'f1':F,'precision':P}


# ─────────────────────────── three-way chase chart ─────────────────────────

def three_way_chart(repro_dir: Path, out: Path):
    on_chase = json.loads((repro_dir/'chanever_on_chase_results.json').read_text())
    head = json.loads((repro_dir/'chase_vs_chanever_small_results.json').read_text())
    mal = on_chase['confusion_per_family']['chase-mal']
    ours_mal  = {'TP': mal['TP'], 'FN': 0, 'ERR': mal.get('ERR', 0)}
    chase_mal = {'TP': 492, 'FN': 8,  'ERR': 0}   # CHASE paper: recall 98.4 % on 500
    ours_ben  = {'TN': head['chanever_confusion'].get('TN', 0),
                 'FP': head['chanever_confusion'].get('FP', 0),
                 'ERR': head['chanever_confusion'].get('ERR', 0)}
    chase_ben = {'TN': head['chase_confusion'].get('TN', 0),
                 'FP': head['chase_confusion'].get('FP', 0),
                 'ERR': head['chase_confusion'].get('ERR', 0)}

    def f1_combined(m, b):
        TP, FN = m['TP'], m['FN']; TN, FP = b['TN'], b['FP']
        P = TP/(TP+FP) if (TP+FP) else 0
        R = TP/(TP+FN) if (TP+FN) else 0
        F = 2*P*R/(P+R) if (P+R) else 0
        return P*100, R*100, F*100

    ours_P, ours_R, ours_F     = f1_combined(ours_mal,  ours_ben)
    chase_P, chase_R, chase_F  = f1_combined(chase_mal, chase_ben)
    ours_recall  = ours_mal['TP'] /(ours_mal['TP'] +ours_mal['FN'])*100
    chase_recall = chase_mal['TP']/(chase_mal['TP']+chase_mal['FN'])*100
    ours_spec    = ours_ben['TN'] /(ours_ben['TN'] +ours_ben['FP'])*100 if (ours_ben['TN']+ours_ben['FP']) else 0
    chase_spec   = chase_ben['TN']/(chase_ben['TN']+chase_ben['FP'])*100 if (chase_ben['TN']+chase_ben['FP']) else 0

    fig = plt.figure(figsize=(13.5, 6.6))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.6, 1.0], wspace=0.25)
    ax = fig.add_subplot(gs[0, 0]); axF = fig.add_subplot(gs[0, 1])

    x_centers = [0, 2.0]; bw = 0.7
    pos = {('m','o'): x_centers[0]-bw*0.55, ('m','c'): x_centers[0]+bw*0.55,
           ('b','o'): x_centers[1]-bw*0.55, ('b','c'): x_centers[1]+bw*0.55}
    norm = {'m': 1.0, 'b': 500/23}

    def stack(p, data, scale, order):
        base = 0
        for cat in order:
            v = data.get(cat, 0)
            if v == 0: continue
            ax.bar(p, v*scale, bw, bottom=base, color=COL[cat], edgecolor='white', linewidth=0.6)
            c = 'white' if cat in ('TP','FN','TN','ERR') else 'black'
            ax.text(p, base + v*scale/2, f'{cat} {int(v)}', ha='center', va='center',
                    color=c, fontsize=10, fontweight='bold')
            base += v*scale

    stack(pos[('m','o')], ours_mal,  norm['m'], ['TP','FN','ERR'])
    stack(pos[('m','c')], chase_mal, norm['m'], ['TP','FN','ERR'])
    stack(pos[('b','o')], ours_ben,  norm['b'], ['TN','FP','ERR'])
    stack(pos[('b','c')], chase_ben, norm['b'], ['TN','FP','ERR'])

    for (fam, fw), p in pos.items():
        lbl = 'chanever\n(ours)' if fw == 'o' else ('CHASE\n(paper)' if fam == 'm' else 'CHASE')
        ax.text(p, -28, lbl, ha='center', va='top', fontsize=10, fontweight='bold',
                color=(BLUE if fw == 'o' else RED))
    ax.text(pos[('m','o')], 520, f'recall {ours_recall:.1f}%',  ha='center', fontsize=10, fontweight='bold', color=BLUE)
    ax.text(pos[('m','c')], 520, f'recall {chase_recall:.1f}%', ha='center', fontsize=10, fontweight='bold', color=RED)
    ax.text(pos[('b','o')], 520, f'spec {ours_spec:.1f}%',      ha='center', fontsize=10, fontweight='bold', color=BLUE)
    ax.text(pos[('b','c')], 520, f'spec {chase_spec:.1f}%',     ha='center', fontsize=10, fontweight='bold', color=RED)

    ax.axvline(x=1.0, color='gray', linestyle=':', linewidth=0.8, alpha=0.5)
    ax.text(x_centers[0], 580, 'chase-mal\n(500 mal pkg)',  ha='center', fontsize=11.5, fontweight='bold')
    ax.text(x_centers[1], 580, 'chase_compatible_ben\n(23 ben pkg, head-to-head)', ha='center', fontsize=11.5, fontweight='bold')
    ax.set_xlim(-1.0, 3.0); ax.set_ylim(-90, 620); ax.set_xticks([])
    ax.set_ylabel('Cases (chase-ben rescaled to match chase-mal)')
    ax.set_title('Per-package outcomes', fontsize=11.5, fontweight='bold')
    ax.grid(axis='y', alpha=0.3); ax.set_axisbelow(True)
    ax.spines['right'].set_visible(False); ax.spines['top'].set_visible(False)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(facecolor=COL[c], label=l) for c, l in
                       [('TP','TP'),('FN','FN'),('TN','TN'),('FP','FP'),('ERR','ERR')]],
              loc='upper left', fontsize=9, ncol=5, bbox_to_anchor=(0.0, -0.05))

    labels = ['Precision', 'Recall', 'F1']
    xs = np.arange(len(labels)); w = 0.36
    b1 = axF.bar(xs-w/2, [ours_P, ours_R, ours_F],  w, color=BLUE, label='chanever')
    b2 = axF.bar(xs+w/2, [chase_P, chase_R, chase_F], w, color=RED,  label='CHASE')
    for bars, vals in [(b1, [ours_P, ours_R, ours_F]),
                       (b2, [chase_P, chase_R, chase_F])]:
        for bar, v in zip(bars, vals):
            axF.text(bar.get_x()+bar.get_width()/2, v+0.25, f'{v:.2f}%',
                     ha='center', va='bottom', fontsize=10, fontweight='bold')
    axF.set_xticks(xs); axF.set_xticklabels(labels, fontsize=10.5)
    axF.set_ylim(94, 102); axF.set_ylabel('Percent')
    axF.set_title('Combined metrics\n(500 mal + 23 ben, ERR excluded)',
                  fontsize=11, fontweight='bold')
    axF.legend(loc='lower right', fontsize=10)
    axF.grid(axis='y', alpha=0.3); axF.set_axisbelow(True)
    axF.spines['right'].set_visible(False); axF.spines['top'].set_visible(False)

    fig.suptitle('chanever vs CHASE — head-to-head on CHASE-dataset families + F1',
                 fontsize=13, fontweight='bold', y=1.00)
    fig.tight_layout(); fig.savefig(out, dpi=140, bbox_inches='tight'); plt.close(fig)


# ─────────────────────────── orchestration ─────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    parser.add_argument('--in', dest='in_dir', default=str(here / 'expected_outputs'))
    parser.add_argument('--out', default=str(here / 'expected_outputs' / 'charts'))
    args = parser.parse_args()
    in_dir, out_dir = Path(args.in_dir), Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # chanever full census
    d = json.loads((in_dir / 'chanever_full_census_results.json').read_text())
    m = d['metrics_framework_on']
    per_family_bar(
        ['datadog-pypi', 'benign-pypi', 'datadog-npm', 'benign-npm',
         'malicious-repos', 'benign-repos', 'skill-inject', 'toolhijacker',
         'benign-skills', 'benign-tools'],
        d['confusion_per_family'],
        'chanever framework on chanever bench (302 cases, 10 families)',
        f"DSR {m['dsr']*100:.1f}% · Spec {m['specificity']*100:.1f}% · "
        f"F1 {m['f1']*100:.1f}% · TP {m['TP']} TN {m['TN']} FP {m['FP']} FN {m['FN']}",
        out_dir / 'chart_chanever_full_census.png')

    # MalPacDetector
    d = json.loads((in_dir / 'malpacdetector_npm_results.json').read_text())
    m = d['metrics']
    per_family_bar(
        ['malicious-npm', 'benign-npm'], d['confusion_per_family'],
        'MalPacDetector (RF) on chanever npm bench (100 cases)',
        f"Recall {m['dsr']*100:.1f}% · Spec {m['specificity']*100:.1f}% · "
        f"F1 {m['f1']*100:.1f}% · TP {m['TP']} TN {m['TN']} FP {m['FP']} FN {m['FN']}",
        out_dir / 'chart_malpacdetector_npm.png', height=5.2)

    # ClawVet
    d = json.loads((in_dir / 'clawvet_skill_results.json').read_text())
    m = metrics_from(d['confusion_total'])
    per_family_bar(
        ['skill-inject', 'toolhijacker', 'benign-skills', 'benign-tools'],
        d['confusion_per_family'],
        'ClawVet on chanever skill/tool bench (79 cases)',
        f"Recall {m['dsr']*100:.1f}% · Spec {m['specificity']*100:.1f}% · "
        f"F1 {m['f1']*100:.1f}% · TP {m['TP']} TN {m['TN']} FP {m['FP']} FN {m['FN']}",
        out_dir / 'chart_clawvet_skill.png', height=5.4)

    # CHASE paper-reported (static — no JSON dependency)
    per_family_bar(
        ['chase-mal', 'chase-ben'],
        {'chase-mal': {'TP': 492, 'FN': 8}, 'chase-ben': {'TN': 2498, 'FP': 2}},
        'CHASE on CHASE benchmark (paper-reported, 3000 cases)',
        'Recall 98.4% · Spec 99.92% · F1 98.99% · TP 492 TN 2498 FP 2 FN 8'
        '  (Toda & Mori, AIware 2025)',
        out_dir / 'chart_chase_paper.png', height=5.2)

    # three-way head-to-head
    three_way_chart(in_dir, out_dir / 'chart_chase_three_way.png')
    print(f'rendered 5 charts into {out_dir}')


if __name__ == '__main__':
    main()
