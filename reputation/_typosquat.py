"""Typosquat distance check — flag PyPI/npm names that are 1-2 chars from a
popular package.

This catches the supply-chain attack pattern documented in DataDog and Phylum
reports where attackers register names like ``reqeusts`` / ``urlib3`` /
``lod4sh`` to harvest fat-finger installs. We do NOT keep a complete
ecosystem index — just a curated top-100 per ecosystem suffices because
typosquats almost always target the most-installed names.

Distance threshold:
- 0 (exact match) → not a typosquat (legitimate popular package)
- 1-2 → flag as ``typosquat-suspect`` with the closest target name
- >=3 → distance too far to be confident, skip

Sources for the popular lists:
- PyPI: PyPI Stats top by 30-day downloads (manually curated snapshot)
- npm: most-depended-upon npm packages list (manually curated snapshot)
"""

from __future__ import annotations


# Top PyPI by 30-day downloads (BigQuery PyPI download stats snapshot — May 2025).
# Trimmed to highest-impact targets that show up most often in typosquat reports.
POPULAR_PYPI = {
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "setuptools", "six", "python-dateutil", "numpy", "pyyaml",
    "boto3", "botocore", "s3transfer", "wheel", "pip", "packaging",
    "click", "jmespath", "typing-extensions", "attrs",
    "pyparsing", "fsspec", "platformdirs", "cryptography", "cffi",
    "pyasn1", "rsa", "google-auth", "protobuf", "grpcio",
    "pandas", "scipy", "matplotlib", "tornado", "tqdm",
    "websockets", "aiohttp", "aiosignal", "frozenlist", "multidict",
    "yarl", "lxml", "beautifulsoup4", "soupsieve", "html5lib",
    "jinja2", "markupsafe", "werkzeug", "flask", "itsdangerous",
    "django", "djangorestframework", "fastapi", "starlette", "pydantic",
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymysql",
    "redis", "celery", "kombu", "billiard", "amqp",
    "openssl", "pycparser", "pillow", "scikit-learn", "tensorflow",
    "torch", "transformers", "huggingface-hub", "datasets", "accelerate",
    "openai", "anthropic", "langchain", "tiktoken", "regex",
    "pytest", "pytest-cov", "pytest-asyncio", "pytest-xdist", "mock",
    "tox", "coverage", "black", "isort", "ruff", "mypy",
    "rich", "typer", "colorama", "tabulate", "questionary",
    "pyjwt", "bcrypt", "passlib", "argon2-cffi", "oauthlib",
    "wcwidth", "prompt-toolkit", "ipython", "jedi", "parso",
}

# Top npm by deps.dev "depended-upon" + npm-stat (May 2025 snapshot).
POPULAR_NPM = {
    "lodash", "react", "react-dom", "axios", "express",
    "chalk", "debug", "commander", "semver", "ms",
    "moment", "uuid", "minimist", "tslib", "fs-extra",
    "rxjs", "yargs", "mkdirp", "glob", "rimraf",
    "request", "cheerio", "cors", "body-parser", "dotenv",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "joi",
    "ws", "socket.io", "nodemon", "ts-node", "typescript",
    "vue", "vuex", "next", "nuxt", "vite",
    "webpack", "babel-core", "@babel/core", "@babel/preset-env", "esbuild",
    "prettier", "eslint", "jest", "mocha", "chai",
    "lodash.merge", "lodash.get", "underscore", "ramda",
    "redux", "react-redux", "react-router", "react-router-dom", "styled-components",
    "tailwindcss", "postcss", "autoprefixer", "sass", "less",
    "node-fetch", "got", "isomorphic-fetch", "form-data", "qs",
    "ejs", "handlebars", "pug", "marked", "showdown",
    "winston", "pino", "morgan", "bunyan",
    "mongoose", "sequelize", "knex", "pg", "mysql",
    "graphql", "apollo-server", "apollo-client", "@apollo/client",
    "puppeteer", "playwright", "selenium-webdriver",
    "discord.js", "telegraf", "twilio", "stripe",
}


def _levenshtein(a: str, b: str, *, cutoff: int = 3) -> int:
    """Bounded Levenshtein distance. Returns ``cutoff`` if distance >= cutoff.

    Lowest-touch DP without numpy. Cutoff stops the matrix early to keep this
    O(min(len)*cutoff) instead of O(len*len) for the negative case (most
    package-name pairs are far apart).
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) >= cutoff:
        return cutoff
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best_in_row = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(
                cur[j - 1] + 1,        # insert
                prev[j] + 1,           # delete
                prev[j - 1] + cost,    # substitute
            )
            if cur[j] < best_in_row:
                best_in_row = cur[j]
        if best_in_row >= cutoff:
            return cutoff
        prev = cur
    return min(prev[-1], cutoff)


def check(name: str, ecosystem: str) -> dict:
    """Return a typosquat signal for one package name.

    Output:
        {
          "status": "match" | "near" | "far" | "skipped",
          "ecosystem": "PyPI" | "npm",
          "name": <name>,
          "closest": <closest popular name, or None>,
          "distance": <int>,
          "summary": "<one-line>",
        }
    """
    ecosystem_norm = ecosystem.lower()
    if ecosystem_norm in {"pypi", "py", "python"}:
        popular = POPULAR_PYPI
        eco_label = "PyPI"
    elif ecosystem_norm in {"npm", "javascript", "js"}:
        popular = POPULAR_NPM
        eco_label = "npm"
    else:
        return {
            "status": "skipped",
            "ecosystem": ecosystem,
            "name": name,
            "closest": None,
            "distance": None,
            "summary": f"No popular list for ecosystem {ecosystem!r}",
        }

    name_norm = name.lower()
    if name_norm in popular:
        return {
            "status": "match",
            "ecosystem": eco_label,
            "name": name,
            "closest": name_norm,
            "distance": 0,
            "summary": f"{name} is a known popular {eco_label} package (no typosquat).",
        }
    best_name: str | None = None
    best_dist = 3
    for pop in popular:
        d = _levenshtein(name_norm, pop, cutoff=3)
        if d < best_dist:
            best_dist = d
            best_name = pop
            if d == 1:
                break
    if best_dist >= 3:
        return {
            "status": "far",
            "ecosystem": eco_label,
            "name": name,
            "closest": best_name,
            "distance": best_dist,
            "summary": f"{name} is >2 edits from any popular {eco_label} name — not a typosquat candidate.",
        }
    return {
        "status": "near",
        "ecosystem": eco_label,
        "name": name,
        "closest": best_name,
        "distance": best_dist,
        "summary": (
            f"⚠ {name!r} is only {best_dist} edits from popular package {best_name!r} on {eco_label} — "
            f"possible typosquat."
        ),
    }
