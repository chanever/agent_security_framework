"""
Validateur d'exercices : execute le fichier, verifie la sortie,
et donne un feedback sans reveler la solution.
"""

import ast
import sys
import io
import traceback
from pathlib import Path


def validate_exercise(fichier, concept=None):
    """
    Valide un fichier exercice.
    Retourne un dict avec status, message, hint.
    """
    path = Path(fichier)
    if not path.exists():
        return {
            "status": "error",
            "message": f"Fichier '{fichier}' introuvable.",
            "hint": "Cree le fichier avec les variables demandees."
        }

    try:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        return {
            "status": "error",
            "message": f"Impossible de lire le fichier: {e}",
            "hint": "Verifie que le fichier est accessible."
        }

    # Verifie la syntaxe
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {
            "status": "error",
            "message": f"Erreur de syntaxe ligne {e.lineno}: {e.msg}",
            "hint": f"Verifie les parentheses, les guillemets, et l'indentation vers la ligne {e.lineno}."
        }

    # Execute le code
    namespace = {}
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        exec(code, namespace)
        output = sys.stdout.getvalue()
    except Exception as e:
        sys.stdout = old_stdout
        tb = traceback.format_exc()
        return {
            "status": "error",
            "message": f"Erreur d'execution: {type(e).__name__}: {e}",
            "debug": tb.split("\n")[-4:-1],
            "hint": "Lis la derniere ligne de l'erreur. Que dit-elle ?"
        }
    finally:
        sys.stdout = old_stdout

    # Verifications generiques
    erreurs = []
    reussites = []

    # Verifie qu'il y a des variables definies
    user_vars = {k: v for k, v in namespace.items()
                 if not k.startswith("_") and not callable(v)}
    if user_vars:
        reussites.append(f"{len(user_vars)} variable(s) definie(s)")
    else:
        erreurs.append("Aucune variable definie")

    # Verifie qu'il y a un print ou une sortie
    if output.strip():
        reussites.append(f"Sortie produite ({len(output)} caracteres)")
    else:
        erreurs.append("Aucune sortie (as-tu utilise print() ?)")

    # Verifie les types de base si presents
    for nom, val in user_vars.items():
        if isinstance(val, str):
            reussites.append(f"  {nom}: str OK")
        elif isinstance(val, int):
            reussites.append(f"  {nom}: int OK")
        elif isinstance(val, float):
            reussites.append(f"  {nom}: float OK")
        elif isinstance(val, bool):
            reussites.append(f"  {nom}: bool OK")
        elif isinstance(val, list):
            reussites.append(f"  {nom}: list[{len(val)} elements] OK")
        elif isinstance(val, dict):
            reussites.append(f"  {nom}: dict[{len(val)} cles] OK")
        elif isinstance(val, set):
            reussites.append(f"  {nom}: set[{len(val)} elements] OK")
        elif isinstance(val, tuple):
            reussites.append(f"  {nom}: tuple[{len(val)} elements] OK")

    if erreurs and not reussites:
        return {
            "status": "error",
            "message": "\n".join(erreurs),
            "hint": "Ajoute des variables et un print() pour voir le resultat."
        }

    if erreurs:
        return {
            "status": "partial",
            "reussites": reussites,
            "erreurs": erreurs,
            "hint": "Relis la lecon et verifie ce qui manque."
        }

    return {
        "status": "success",
        "reussites": reussites,
        "message": "Tout est correct ! Passe au concept suivant.",
        "output": output.strip()
    }
