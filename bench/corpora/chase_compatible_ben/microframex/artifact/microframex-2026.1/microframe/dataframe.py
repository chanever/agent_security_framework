class DataFrame:
    def __init__(self, rows, columns=None):

        rows = list(rows)  # 🔥 强制统一
        self.rows = []

        if not rows:
            return

        # ========= dict 输入 =========
        if isinstance(rows[0], dict):
            self.rows = rows
            return

        # ========= row + columns =========
        if not columns:
            columns = list(rows[0])
            rows = rows[1:]

        self.rows = [
            dict(zip(columns, row))
            for row in rows
        ]

    def validate_keys(self, keys):
        cols = set(self.columns)
        keys = set(keys)

        missing = keys - cols
        if missing:
            raise KeyError(f"字段 “{missing}” 不存在")

    @property
    def columns(self):
        if not self.rows:
            return []
        return list(self.rows[0].keys())

    def head(self, n=5):
        return DataFrame(self.rows[:n])

    def groupby(self, *keys):

        # 👉 统一校验
        self.validate_keys(keys)

        groups = {}

        for row in self.rows:

            if len(keys) == 1:
                k = row.get(keys[0])
            else:
                k = tuple(row.get(key) for key in keys)

            groups.setdefault(k, []).append(row)

        return {k: DataFrame(v) for k, v in groups.items()}

    def __repr__(self):
        n = min(5, len(self.rows))
        preview = self.rows[:n]

        col_count = len(self.columns)

        lines = [f"DataFrame(rows={len(self.rows)}, cols={col_count})("]

        for row in preview:
            lines.append(f"  {row}")

        if len(self.rows) > 5:
            lines.append(f"  ...")

        lines.append(")")
        return "\n".join(lines)