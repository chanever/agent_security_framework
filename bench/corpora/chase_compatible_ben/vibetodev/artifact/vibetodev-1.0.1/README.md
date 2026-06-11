# VibeToDev

Transforme n'importe quel projet Python vibecodé en parcours d'apprentissage structuré.

## Installation

```bash
pip install vibetodev
```

Ou depuis les sources :

```bash
git clone <URL_DU_DEPOT>
cd vibetodev
pip install .
```

## Utilisation

```bash
# Scanner un projet et generer un vault Obsidian
vibetodev scan /chemin/vers/mon_projet --output /chemin/vers/mon_vault

# Valider un exercice
vibetodev check mon_exercice.py

# Initialiser vibetodev dans un projet
vibetodev init /chemin/vers/mon_projet
```

## Comment ca marche

1. **Scan** — Analyse AST de tous les fichiers Python, extrait 50+ concepts avec leur position exacte
2. **Categorisation** — Les concepts sont regroupes en modules pedagogiques adaptes au projet
3. **Generation** — Cree un vault Obsidian avec lecons, exemples de code, et exercices
4. **Validation** — Execute et verifie les exercices sans donner la solution

## Licence

MIT
