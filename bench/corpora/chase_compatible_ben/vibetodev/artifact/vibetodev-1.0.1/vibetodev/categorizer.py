"""
Categorise les concepts extraits en modules pedagogiques.
Assigne un niveau (debutant/intermediaire/avance) et un ordre.
"""

from collections import defaultdict

# Mapping concept -> module
CONCEPT_MODULE = {
    # Module 1 : Variables
    "type_str": 1, "type_int": 1, "type_bool": 1, "type_float": 1,
    "type_none": 1, "type_bytes": 1, "chaine": 1,
    "assignation": 1, "assignation_multiple": 1, "assignation_typee": 1,
    "assignation_augmentee": 1,

    # Module 2 : Fonctions
    "fonction_def": 2, "fonction_async": 2, "return": 2, "yield": 2,
    "type_hint_param": 2, "type_hint_return": 2, "docstring": 2,
    "decorateur": 2, "lambda": 2,

    # Module 3 : Controle
    "condition_if": 3, "condition_elif": 3, "condition_else": 3,
    "boucle_for": 3, "boucle_while": 3, "boucle_async_for": 3,
    "break": 3, "continue": 3, "ternaire": 3,

    # Module 4 : Gestion d'erreurs
    "try_except": 4, "try_finally": 4, "raise": 4,
    "context_manager_with": 4, "context_manager_async_with": 4,

    # Module 5 : Collections
    "type_list": 5, "type_dict": 5, "type_set": 5, "type_tuple": 5,
    "comprehension_liste": 5, "comprehension_dict": 5, "comprehension_set": 5,
    "assignation_index": 5, "slice": 5,

    # Module 6 : Operations
    "appel_fonction": 6, "appel_methode": 6,
    "operateur_comparaison": 6, "operateur_logique": 6,
    "fstring": 6, "binop_Add": 6, "binop_Sub": 6, "binop_Mult": 6,
    "binop_Div": 6, "unpacking": 6, "walrus_operator": 6,

    # Module 7 : Imports
    "import_module": 7, "import_from": 7,

    # Module 8 : Classes et Objets
    "class_def": 8,
    "assignation_attr": 8,

    # Module 9 : Programmation avancee
    # (tout ce qui n'a pas encore ete categorise)
}

NOMS_MODULES = {
    1: "01_Variables_et_Types",
    2: "02_Fonctions",
    3: "03_Structures_de_Controle",
    4: "04_Gestion_d_Erreurs",
    5: "05_Collections",
    6: "06_Operations_et_Appels",
    7: "07_Imports_et_Modules",
    8: "08_Classes_et_Objets",
    9: "09_Concepts_Avances",
}

TITRES_MODULES = {
    1: "Variables et types de donnees",
    2: "Les fonctions",
    3: "Structures de controle",
    4: "Gestion d'erreurs",
    5: "Collections (listes, dicts, sets, tuples)",
    6: "Operations et appels",
    7: "Imports et modules",
    8: "Classes et objets",
    9: "Concepts avances (async, decorateurs, etc.)",
}

NIVEAU_CONCEPT = {
    "type_str": "debutant", "type_int": "debutant", "type_bool": "debutant",
    "type_float": "debutant", "type_none": "debutant", "chaine": "debutant",
    "assignation": "debutant", "assignation_multiple": "debutant",
    "assignation_augmentee": "debutant",
    "fonction_def": "debutant", "return": "debutant",
    "docstring": "debutant",
    "condition_if": "debutant", "condition_else": "debutant",
    "boucle_for": "debutant",
    "type_list": "debutant", "type_dict": "debutant",
    "fstring": "debutant",
    "import_module": "debutant", "import_from": "debutant",
    "appel_fonction": "debutant",
    "appel_methode": "debutant",
    "operateur_comparaison": "debutant",
    "operateur_logique": "debutant",
    "type_float": "debutant",
    "break": "debutant", "continue": "debutant",
    "condition_elif": "intermediaire",
    "assignation_index": "intermediaire",
    "type_set": "intermediaire", "type_tuple": "intermediaire",
    "assignation_typee": "intermediaire",
    "type_hint_param": "intermediaire",
    "try_except": "intermediaire",
    "context_manager_with": "intermediaire",
    "comprehension_liste": "intermediaire",
    "decorateur": "avance",
    "lambda": "avance",
    "yield": "avance",
    "class_def": "avance",
    "comprehension_dict": "avance",
    "walrus_operator": "avance",
    "fonction_async": "avance",
    "boucle_async_for": "avance",
    "context_manager_async_with": "avance",
}


def categorize_concepts(concepts_bruts):
    """
    Prend {concept: [occurences]} et retourne {module_id: {concept: occurences}}.
    """
    modules = defaultdict(lambda: defaultdict(list))

    for concept, occs in concepts_bruts.items():
        module_id = CONCEPT_MODULE.get(concept, 9)  # defaut: avance
        modules[module_id][concept] = occs

    return dict(sorted(modules.items()))
