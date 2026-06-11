"""
Scanner AST : analyse tous les fichiers Python d'un projet
et extrait chaque concept avec sa position exacte (fichier:ligne).
"""

import ast
import os
from pathlib import Path
from collections import defaultdict

IGNORE_DIRS = {"__pycache__", "venv", ".venv", "node_modules", ".git", ".vibetodev", ".vibetodev-vault"}
IGNORE_FILES = {"__init__.py"}


class ConceptExtractor(ast.NodeVisitor):
    """Visite l'AST et extrait les concepts avec fichier:ligne."""

    def __init__(self, fichier_rel, lignes_source):
        self.fichier = fichier_rel
        self.lignes = lignes_source
        self.concepts = defaultdict(list)

    def _extraire_code(self, node):
        debut = max(0, getattr(node, 'lineno', 1) - 1)
        fin = getattr(node, 'end_lineno', debut + 1) or (debut + 1)
        if fin > len(self.lignes):
            fin = len(self.lignes)
        return "".join(self.lignes[debut:fin]).strip()

    def _add(self, concept, node):
        self.concepts[concept].append({
            "fichier": self.fichier,
            "ligne": getattr(node, 'lineno', 0),
            "code": self._extraire_code(node),
        })

    def visit_Import(self, node):
        for alias in node.names:
            self._add("import_module", node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        self._add("import_from", node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._add("fonction_def", node)
        if node.decorator_list:
            self._add("decorateur", node)
        for a in node.args.args:
            if a.annotation:
                self._add("type_hint_param", a)
        if node.returns:
            self._add("type_hint_return", node)
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            self._add("docstring", node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._add("fonction_async", node)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self._add("class_def", node)
        self.generic_visit(node)

    def visit_Lambda(self, node):
        self._add("lambda", node)
        self.generic_visit(node)

    def visit_Return(self, node):
        self._add("return", node)
        self.generic_visit(node)

    def visit_Yield(self, node):
        self._add("yield", node)
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                self._add("assignation_multiple", node)
            elif isinstance(target, ast.Name):
                self._add("assignation", node)
            elif isinstance(target, ast.Subscript):
                self._add("assignation_index", node)
            elif isinstance(target, ast.Attribute):
                self._add("assignation_attr", node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._add("assignation_typee", node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._add("assignation_augmentee", node)
        self.generic_visit(node)

    def visit_For(self, node):
        self._add("boucle_for", node)
        self.generic_visit(node)

    def visit_AsyncFor(self, node):
        self._add("boucle_async_for", node)
        self.generic_visit(node)

    def visit_While(self, node):
        self._add("boucle_while", node)
        self.generic_visit(node)

    def visit_Break(self, node):
        self._add("break", node)
        self.generic_visit(node)

    def visit_Continue(self, node):
        self._add("continue", node)
        self.generic_visit(node)

    def visit_If(self, node):
        self._add("condition_if", node)
        if node.orelse:
            if isinstance(node.orelse[0], ast.If):
                self._add("condition_elif", node.orelse[0])
            else:
                self._add("condition_else", node)
        self.generic_visit(node)

    def visit_Try(self, node):
        self._add("try_except", node)
        if node.finalbody:
            self._add("try_finally", node)
        self.generic_visit(node)

    def visit_Raise(self, node):
        self._add("raise", node)
        self.generic_visit(node)

    def visit_With(self, node):
        self._add("context_manager_with", node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node):
        self._add("context_manager_async_with", node)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        self._add("comprehension_liste", node)
        self.generic_visit(node)

    def visit_DictComp(self, node):
        self._add("comprehension_dict", node)
        self.generic_visit(node)

    def visit_SetComp(self, node):
        self._add("comprehension_set", node)
        self.generic_visit(node)

    def visit_List(self, node):
        if not isinstance(node.ctx, ast.Store):
            self._add("type_list", node)
        self.generic_visit(node)

    def visit_Dict(self, node):
        self._add("type_dict", node)
        self.generic_visit(node)

    def visit_Set(self, node):
        self._add("type_set", node)
        self.generic_visit(node)

    def visit_Tuple(self, node):
        self._add("type_tuple", node)
        self.generic_visit(node)

    def visit_Constant(self, node):
        val = node.value
        if isinstance(val, str):
            self._add("chaine" if val == "" else "type_str", node)
        elif isinstance(val, bool):
            self._add("type_bool", node)
        elif isinstance(val, int):
            self._add("type_int", node)
        elif isinstance(val, float):
            self._add("type_float", node)
        elif val is None:
            self._add("type_none", node)
        elif isinstance(val, bytes):
            self._add("type_bytes", node)
        self.generic_visit(node)

    def visit_Compare(self, node):
        self._add("operateur_comparaison", node)
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self._add("operateur_logique", node)
        self.generic_visit(node)

    def visit_BinOp(self, node):
        op_type = type(node.op).__name__
        self._add(f"binop_{op_type}", node)
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            self._add("appel_methode", node)
        elif isinstance(node.func, ast.Name):
            self._add("appel_fonction", node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        self._add("fstring", node)
        self.generic_visit(node)

    def visit_Slice(self, node):
        self._add("slice", node)
        self.generic_visit(node)

    def visit_IfExp(self, node):
        self._add("ternaire", node)
        self.generic_visit(node)

    def visit_Starred(self, node):
        self._add("unpacking", node)
        self.generic_visit(node)

    def visit_walrus(self, node):
        """:= operateur morse (Python 3.8+)"""
        self._add("walrus_operator", node)
        self.generic_visit(node)


def scan_project(source_dir, recursive=True):
    """
    Scanne un projet et retourne {concept: [occurences]}.
    Chaque occurrence a: fichier, ligne, code.
    """
    source = Path(source_dir)
    tous = defaultdict(list)
    fichiers_trouves = []

    if recursive:
        for root, dirs, files in os.walk(source):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                if f.endswith(".py") and f not in IGNORE_FILES:
                    fichiers_trouves.append(Path(root) / f)
    else:
        for f in source.glob("*.py"):
            if f.name not in IGNORE_FILES:
                fichiers_trouves.append(f)

    for chemin in sorted(set(fichiers_trouves)):
        try:
            rel = str(chemin.relative_to(source.parent)) if source.parent in chemin.parents else str(chemin)
        except ValueError:
            rel = str(chemin)

        try:
            with open(chemin, "r", encoding="utf-8", errors="replace") as f:
                lignes = f.readlines()
        except Exception:
            continue

        try:
            arbre = ast.parse("".join(lignes))
        except SyntaxError:
            continue

        extracteur = ConceptExtractor(rel, lignes)
        extracteur.visit(arbre)

        for concept, occs in extracteur.concepts.items():
            tous[concept].extend(occs)

    return dict(tous)
