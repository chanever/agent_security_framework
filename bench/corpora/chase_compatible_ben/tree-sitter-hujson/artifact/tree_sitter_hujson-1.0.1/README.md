# tree-sitter-hujson

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![SemVer](https://img.shields.io/badge/semver-2.0.0-blue)](https://semver.org/spec/v2.0.0.html)
[![tree-sitter ABI](https://img.shields.io/badge/tree--sitter%20ABI-14-blue)](https://tree-sitter.github.io/tree-sitter/)
[![CI](https://github.com/ggfevans/tree-sitter-hujson/actions/workflows/ci.yml/badge.svg)](https://github.com/ggfevans/tree-sitter-hujson/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/ggfevans/tree-sitter-hujson?logo=github)](https://github.com/ggfevans/tree-sitter-hujson/releases/latest)
[![npm](https://img.shields.io/npm/v/tree-sitter-hujson?logo=npm)](https://www.npmjs.com/package/tree-sitter-hujson)
[![PyPI](https://img.shields.io/pypi/v/tree-sitter-hujson?logo=pypi&logoColor=white)](https://pypi.org/project/tree-sitter-hujson/)
[![crates.io](https://img.shields.io/crates/v/tree-sitter-hujson?logo=rust)](https://crates.io/crates/tree-sitter-hujson)

A [tree-sitter](https://tree-sitter.github.io) grammar for [HuJSON](https://github.com/tailscale/hujson) (Human JSON), also known as [JWCC](https://nigeltao.github.io/blog/2021/json-with-commas-comments.html) (JSON With Commas and Comments).

HuJSON is a strict superset of JSON that adds exactly two features:

- **C-style comments**: line comments (`//`) and block comments (`/* */`)
- **Trailing commas**: an optional trailing comma after the last element in arrays and objects

All valid JSON is valid HuJSON. HuJSON intentionally rejects every other extension (unquoted keys, hex literals, `Infinity`/`NaN`, single-quoted strings, and so on); object keys must be quoted strings, exactly as in standard JSON.

The grammar registers both the `.hujson` and `.jwcc` file extensions.

## Installation

The grammar is published to npm, PyPI, and crates.io. Each package exposes the compiled language for use with that ecosystem's tree-sitter bindings.

Each example needs the `tree-sitter` runtime for that language alongside this grammar.

### npm (Node.js)

```bash
npm install tree-sitter tree-sitter-hujson
```

```js
const Parser = require("tree-sitter");
const HuJSON = require("tree-sitter-hujson");

const parser = new Parser();
parser.setLanguage(HuJSON);
```

### PyPI (Python)

```bash
pip install "tree-sitter-hujson[core]"
```

```python
import tree_sitter_hujson
from tree_sitter import Language, Parser

parser = Parser(Language(tree_sitter_hujson.language()))
```

### crates.io (Rust)

```bash
cargo add tree-sitter tree-sitter-hujson
```

```rust
let mut parser = tree_sitter::Parser::new();
parser
    .set_language(&tree_sitter_hujson::language())
    .expect("loading HuJSON grammar");
```

### Go, Swift, and C

These bindings ship in the repository and are consumed directly from the tagged source rather than a package registry.

## Editor support

- **Zed**: install the [`ggfevans/zed-hujson`](https://github.com/ggfevans/zed-hujson) extension. This is the only editor integration maintained and tested here.
- **Other tree-sitter hosts** (for example Neovim via nvim-treesitter, or Helix): this is a standard tree-sitter grammar and can be registered through each host's normal grammar mechanism.

Markdown code blocks fenced as ` ```hujson ` are highlighted in editors that resolve fence languages by name (verified in Zed). This works through the declared language scope and name; it needs no `injections.scm` on the grammar side, because the host Markdown grammar supplies the injection.

## Provenance

Forked from [`tree-sitter/tree-sitter-json`](https://github.com/tree-sitter/tree-sitter-json) at commit [`001c28d`](https://github.com/tree-sitter/tree-sitter-json/commit/001c28d7a29832b06b0e831ec77845553c89b56d). The upstream grammar already supported comments, so HuJSON support needed only two changes:

1. **Trailing commas.** The `commaSep` helper now allows an optional trailing comma:

   ```js
   function commaSep1(rule) {
     return seq(rule, repeat(seq(",", rule)), optional(","));
   }
   ```

2. **String-only object keys.** Upstream tree-sitter-json accepts numeric object keys (`choice($.string, $.number)`); HuJSON restricts keys to strings to match standard JSON, so bare numeric keys are parse errors. This tightened in v0.2.0.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, the test suite, and the release process.

## Licence

[MIT](LICENSE), matching the upstream tree-sitter-json licence.
