"""
Genere un vault Obsidian complet avec lecons, exercices et liens vers le code.
"""

import os
from pathlib import Path
from collections import defaultdict

from .categorizer import NOMS_MODULES, TITRES_MODULES, NIVEAU_CONCEPT

EXPLICATIONS = {
    "type_str": "Une **chaine** (str) est du texte entre guillemets.",
    "type_int": "Un **entier** (int) est un nombre sans virgule.",
    "type_bool": "Un **booleen** (bool) vaut True ou False.",
    "type_float": "Un **float** est un nombre decimal.",
    "type_none": "**None** represente l'absence de valeur.",
    "chaine": "Une **chaine vide** \"\" est une chaine sans caractere.",
    "assignation": "L'**assignation** (=) stocke une valeur dans une variable.",
    "assignation_multiple": "L'**assignation multiple** (=) assigne plusieurs variables en une ligne.",
    "assignation_typee": "L'**assignation typee** (=) avec annotation de type.",
    "assignation_augmentee": "L'assignation **augmentee** (+=, -=, etc.) combine operation et assignation.",
    "fonction_def": "Une **fonction** est un bloc de code reutilisable defini avec `def`.",
    "fonction_async": "Une **fonction asynchrone** utilise `async def`.",
    "return": "**return** renvoie une valeur depuis une fonction.",
    "yield": "**yield** transforme une fonction en generateur.",
    "type_hint_param": "Les **type hints** (`param: type`) indiquent le type attendu.",
    "type_hint_return": "Le **type hint de retour** (`-> type`) indique le type de retour.",
    "docstring": "Une **docstring** (\"""...\""") decrit ce que fait la fonction.",
    "decorateur": "Un **decorateur** (@) ajoute un comportement a une fonction.",
    "lambda": "Une **lambda** est une fonction anonyme courte.",
    "condition_if": "**if** execute un bloc si la condition est vraie.",
    "condition_elif": "**elif** teste une autre condition.",
    "condition_else": "**else** s'execute si tout est faux.",
    "boucle_for": "**for** parcourt chaque element d'une collection.",
    "boucle_while": "**while** repete tant que la condition est vraie.",
    "boucle_async_for": "**async for** parcourt un iterateur asynchrone.",
    "break": "**break** sort de la boucle immediatement.",
    "continue": "**continue** passe a l'iteration suivante.",
    "ternaire": "Le **ternaire** (`x if cond else y`) est un if en une ligne.",
    "try_except": "**try/except** capture les erreurs sans planter.",
    "try_finally": "**finally** s'execute toujours, erreur ou pas.",
    "raise": "**raise** declenche une erreur volontairement.",
    "context_manager_with": "**with** gere automatiquement les ressources.",
    "context_manager_async_with": "**async with** pour les contextes asynchrones.",
    "type_list": "Une **liste** `[]` est une collection ordonnee et modifiable.",
    "type_dict": "Un **dict** `{}` associe des cles a des valeurs.",
    "type_set": "Un **set** `{}` est un ensemble sans doublon.",
    "type_tuple": "Un **tuple** `()` est immuable.",
    "comprehension_liste": "Une **comprehension** cree une liste en une ligne.",
    "comprehension_dict": "Une **comprehension** cree un dict en une ligne.",
    "comprehension_set": "Une **comprehension** cree un set en une ligne.",
    "assignation_index": "Modifie un element par son index ou sa cle.",
    "slice": "Le **slicing** `[debut:fin:pas]` extrait une portion.",
    "appel_fonction": "**appel de fonction** () execute une fonction.",
    "appel_methode": "Une **methode** . est une fonction attachee a un objet.",
    "operateur_comparaison": "Compare avec ==, !=, <, >, in, etc.",
    "operateur_logique": "Combine avec **and**, **or**, **not**.",
    "fstring": "Les **f-strings** f\"...\" integrent des variables.",
    "import_module": "**import module** importe tout un module.",
    "import_from": "**from module import** importe specifiquement.",
    "class_def": "Une **classe** definit un nouveau type d'objet.",
    "assignation_attr": "Modifie un attribut d'objet (`objet.attr = ...`).",
    "unpacking": "L'**unpacking** (`*args`, `**kwargs`) decompose des sequences.",
    "walrus_operator": "L'**operateur morse** (:=) assigne dans une expression.",
}


def generate_vault(modules, concepts_bruts, output_dir):
    """Genere le vault Obsidian dans output_dir."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    obsidian_dir = output / ".obsidian"
    obsidian_dir.mkdir(exist_ok=True)

    _generate_index(modules, concepts_bruts, output)
    _generate_obsidian_config(obsidian_dir)

    max_module = max(modules.keys()) if modules else 9
    for module_id, concepts in modules.items():
        _generate_module(module_id, concepts, output, max_module)

    print(f"Vault genere dans {output}/")
    print(f"  -> {len(modules)} modules")
    print(f"  -> {sum(len(c) for c in concepts_bruts.values())} concepts au total")


def _generate_obsidian_config(obsidian_dir):
    """Cree la config minimale Obsidian."""
    core = {
        "file-explorer": True, "global-search": True, "switcher": True,
        "graph": True, "backlink": True, "outgoing-link": True,
        "tag-pane": True, "page-preview": True, "templates": True,
        "command-palette": True, "outline": True, "word-count": True,
        "daily-notes": False,
    }
    with open(obsidian_dir / "core-plugins.json", "w", encoding="utf-8") as f:
        import json
        json.dump(core, f, indent=2)

    app = {}
    with open(obsidian_dir / "app.json", "w", encoding="utf-8") as f:
        json.dump(app, f, indent=2)


def _generate_index(modules, concepts_bruts, output):
    """Genere la page d'accueil du vault."""
    path = output / "Index.md"
    total_concepts = len(concepts_bruts)
    total_occ = sum(len(v) for v in concepts_bruts.values())

    with open(path, "w", encoding="utf-8") as f:
        f.write("# VibeToDev — Parcours d'apprentissage\n\n")
        f.write("Vault genere automatiquement par analyse AST.\n\n")
        f.write(f"- **{total_concepts} concepts** distincts\n")
        f.write(f"- **{total_occ} occurrences** dans le code\n\n")

        f.write("## Modules\n\n")
        f.write("| Module | Contenu |\n")
        f.write("|--------|--------|\n")
        for mid in sorted(modules.keys()):
            nom = NOMS_MODULES.get(mid, f"{mid:02d}")
            titre = TITRES_MODULES.get(mid, f"Module {mid}")
            concepts_count = sum(len(v) for v in modules[mid].values())
            f.write(f"| [[{nom}/Lecon|Module {mid}]] | {titre} ({concepts_count} occ) |\n")

        f.write("\n## Tous les concepts\n\n")
        f.write("| Concept | Niveau | Occurrences |\n")
        f.write("|---------|--------|------------|\n")
        for concept in sorted(concepts_bruts.keys()):
            niveau = NIVEAU_CONCEPT.get(concept, "intermediaire")
            occ = len(concepts_bruts[concept])
            f.write(f"| {concept} | {niveau} | {occ} |\n")


def _generate_module(module_id, concepts, output, max_module=9):
    """Genere la lecon pour un module."""
    nom_dossier = NOMS_MODULES.get(module_id, f"{module_id:02d}")
    titre = TITRES_MODULES.get(module_id, f"Module {module_id}")
    dossier = output / nom_dossier
    dossier.mkdir(exist_ok=True)

    path = dossier / "Lecon.md"
    total_occ_module = sum(len(v) for v in concepts.values())

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Module {module_id} : {titre}\n\n")
        f.write(f"> {total_occ_module} occurrences dans le projet\n\n")

        for concept in sorted(concepts.keys()):
            occs = concepts[concept]
            nom_concept = concept.replace("_", " ").title()
            explication = EXPLICATIONS.get(concept, "")
            niveau = NIVEAU_CONCEPT.get(concept, "intermediaire")

            f.write(f"## {nom_concept}\n")
            f.write(f"_{len(occs)} occurrences | Niveau: {niveau}_\n\n")

            if explication:
                f.write(f"{explication}\n\n")

            # Exemples de code
            f.write("### Dans le code\n\n")
            for i, occ in enumerate(occs[:3]):
                f.write(f"**Exemple {i+1}** — `{occ['fichier']}:{occ['ligne']}`\n\n")
                f.write("```python\n")
                f.write(f"{occ['code']}\n")
                f.write("```\n\n")

            # Autres occurrences
            if len(occs) > 3:
                par_fichier = defaultdict(list)
                for occ in occs[3:]:
                    par_fichier[occ["fichier"]].append(occ["ligne"])
                f.write(f"**{len(occs) - 3} autres occurrences :**\n\n")
                for fichier, lignes in sorted(par_fichier.items()):
                    lignes_str = ", ".join(str(l) for l in lignes[:5])
                    if len(lignes) > 5:
                        lignes_str += f", ... ({len(lignes) - 5} de plus)"
                    f.write(f"- `{fichier}` : lignes {lignes_str}\n")
                f.write("\n")

            # Mini-exercice genere
            f.write("### Mini-exercice\n\n")
            f.write("```python\n")
            f.write(_generer_exercice(concept))
            f.write("\n```\n\n")

            f.write("---\n\n")

        # Navigation
        f.write("## Navigation\n\n")
        if module_id > 1:
            prev = NOMS_MODULES.get(module_id - 1)
            f.write(f"- [[../{prev}/Lecon|Module {module_id - 1}]]\n")
        if module_id < max_module:
            next_mod = NOMS_MODULES.get(module_id + 1)
            f.write(f"- [[../{next_mod}/Lecon|Module {module_id + 1}]]\n")
        f.write("- [[Index|Retour a l'accueil]]\n")


def _generer_exercice(concept):
    """Genere un mini-exercice adapte au concept."""
    exercices = {
        "type_str": 'nom = "VotrePrenom"\nprint(type(nom))\nprint(nom.upper())',
        "type_int": 'age = 25\nannee = 2026 - age\nprint(annee)',
        "type_bool": 'est_actif = True\nif est_actif:\n    print("Actif")',
        "type_float": 'prix = 19.99\ntva = prix * 0.2\nprint(tva)',
        "type_none": 'resultat = None\nif resultat is None:\n    print("Pas de resultat")',
        "assignation": 'nom = "Sophie"\nage = 28\nprint(nom, age)',
        "fonction_def": 'def saluer(nom):\n    return f"Bonjour {nom}"\nprint(saluer("Sophie"))',
        "return": 'def addition(a, b):\n    return a + b\nprint(addition(3, 4))',
        "condition_if": 'note = 15\nif note >= 10:\n    print("Reussi")',
        "boucle_for": 'noms = ["Alice", "Bob", "Charlie"]\nfor n in noms:\n    print(n)',
        "try_except": 'try:\n    x = 1 / 0\nexcept ZeroDivisionError:\n    print("Division par zero")',
        "type_list": 'fruits = ["pomme", "banane"]\nfruits.append("kiwi")\nprint(fruits[0])',
        "type_dict": 'profil = {"nom": "Alice", "age": 30}\nprint(profil["nom"])',
        "type_set": 'a = {"x", "y"}\nb = {"y", "z"}\nprint(a & b)  # intersection',
        "type_tuple": 'coords = (48.85, 2.35)\nprint(coords[0])',
        "comprehension_liste": 'nombres = [1, 2, 3, 4, 5]\npairs = [n for n in nombres if n % 2 == 0]\nprint(pairs)',
        "appel_fonction": 'print("Hello")\nlen([1, 2, 3])',
        "appel_methode": 'texte = "Bonjour"\nprint(texte.lower())\nprint(texte.upper())',
        "fstring": 'nom = "Sophie"\nprint(f"Bonjour {nom}")',
        "import_module": 'import math\nprint(math.sqrt(16))',
        "import_from": 'from math import sqrt\nprint(sqrt(16))',
        "decorateur": 'def mon_decorateur(f):\n    def wrapper():\n        print("Avant")\n        f()\n        print("Apres")\n    return wrapper\n\n@mon_decorateur\ndef dire_bonjour():\n    print("Bonjour")',
        "lambda": 'carre = lambda x: x ** 2\nprint(carre(5))',
        "class_def": 'class Chien:\n    def __init__(self, nom):\n        self.nom = nom\n    def aboyer(self):\n        return "Woof"\n\nmedor = Chien("Medor")\nprint(medor.aboyer())',
        "context_manager_with": 'with open("test.txt", "w") as f:\n    f.write("Hello")',
        "break": 'for i in range(10):\n    if i == 5:\n        break\n    print(i)',
        "continue": 'for i in range(5):\n    if i == 2:\n        continue\n    print(i)',
        "operateur_comparaison": 'a, b = 5, 10\nprint(a < b)\nprint(a == b)',
        "operateur_logique": 'age, pays = 20, "FR"\nif age >= 18 and pays == "FR":\n    print("OK")',
        "slice": 'liste = [0, 1, 2, 3, 4, 5]\nprint(liste[1:4])\nprint(liste[::-1])',
        "assignation_index": 'liste = [1, 2, 3]\nliste[0] = 99\nprint(liste)',
        "assignation_multiple": 'a, b, c = 1, 2, 3\nprint(a, b, c)',
        "assignation_augmentee": 'compteur = 0\ncompteur += 1\nprint(compteur)',
        "ternaire": 'age = 20\nstatut = "majeur" if age >= 18 else "mineur"\nprint(statut)',
        "yield": 'def compter(n):\n    for i in range(n):\n        yield i\nfor x in compter(3):\n    print(x)',
        "walrus_operator": 'if (n := len([1, 2, 3])) > 0:\n    print(f"Longueur: {n}")',
    }
    return exercices.get(concept, f'# Exercice: {concept}\n# Ecris du code qui utilise "{concept}"\npass')
