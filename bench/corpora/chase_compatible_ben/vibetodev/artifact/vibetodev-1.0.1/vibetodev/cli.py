"""
CLI principale de vibetodev.
Usage:
    vibetodev scan <chemin_projet> [--output <chemin_vault>]
    vibetodev check <fichier_exercice>
    vibetodev init <chemin_projet>
    vibetodev serve
"""

import argparse
import sys
import os
from pathlib import Path

from .scanner import scan_project
from .categorizer import categorize_concepts
from .generator import generate_vault
from .validator import validate_exercise


def cmd_scan(args):
    """Analyse un projet et genere un vault Obsidian."""
    source = Path(args.source).resolve()
    if not source.exists():
        print(f"Erreur: '{source}' n'existe pas.")
        return 1

    output = Path(args.output).resolve() if args.output else source / ".vibetodev-vault"

    print(f"Scan de {source}...")
    concepts = scan_project(source, args.recursive)

    if not concepts:
        print("Aucun concept trouve.")
        return 1

    total = sum(len(v) for v in concepts.values())
    print(f"-> {len(concepts)} concepts distincts, {total} occurrences")

    print("Categorisation...")
    modules = categorize_concepts(concepts)

    print("Generation du vault Obsidian...")
    generate_vault(modules, concepts, output)

    print(f"\nVault cree dans: {output}")
    print(f"Ouvre ce dossier dans Obsidian pour voir les lecons.")
    return 0


def cmd_check(args):
    """Valide un exercice."""
    fichier = Path(args.fichier).resolve()
    if not fichier.exists():
        print(f"Erreur: '{fichier}' introuvable.")
        return 1

    result = validate_exercise(fichier, args.concept)
    if result["status"] == "success":
        print("RESULTAT: VALIDE")
        for r in result.get("reussites", []):
            print(f"  [OK] {r}")
        print(result.get("message", ""))
        return 0
    elif result["status"] == "partial":
        print("RESULTAT: PARTIEL")
        for r in result.get("reussites", []):
            print(f"  [OK] {r}")
        for e in result.get("erreurs", []):
            print(f"  [A CORRIGER] {e}")
        print(f"Indice: {result.get('hint', '')}")
        return 1
    else:
        print("RESULTAT: ERREUR")
        print(result.get("message", ""))
        print(f"Indice: {result.get('hint', '')}")
        return 1


def cmd_init(args):
    """Initialise un projet pour vibetodev."""
    source = Path(args.source).resolve()
    if not source.exists():
        print(f"Erreur: '{source}' n'existe pas.")
        return 1

    vibetodev_dir = source / ".vibetodev"
    vibetodev_dir.mkdir(exist_ok=True)

    print(f"VibeToDev initialise dans {source}")
    print(f"Fichier de config: {vibetodev_dir / 'config.json'}")
    print(f"\nProchaine etape: vibetodev scan {source}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="vibetodev",
        description="Transforme un projet vibecode en parcours d'apprentissage",
    )
    parser.add_argument("--version", action="version", version="vibetodev 1.0.1")

    sub = parser.add_subparsers(dest="command", help="Commande")

    # scan
    p_scan = sub.add_parser("scan", help="Analyser un projet et generer un vault")
    p_scan.add_argument("source", help="Dossier du projet a analyser")
    p_scan.add_argument("-o", "--output", help="Dossier de sortie du vault (defaut: <source>/.vibetodev-vault)")
    p_scan.add_argument("-r", "--recursive", action="store_true", default=True, help="Scan recursif (defaut: True)")
    p_scan.set_defaults(func=cmd_scan)

    # check
    p_check = sub.add_parser("check", help="Valider un exercice")
    p_check.add_argument("fichier", help="Fichier exercice a valider")
    p_check.add_argument("--concept", help="Concept a valider (optionnel)")
    p_check.set_defaults(func=cmd_check)

    # init
    p_init = sub.add_parser("init", help="Initialiser vibetodev dans un projet")
    p_init.add_argument("source", help="Dossier du projet")
    p_init.set_defaults(func=cmd_init)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
