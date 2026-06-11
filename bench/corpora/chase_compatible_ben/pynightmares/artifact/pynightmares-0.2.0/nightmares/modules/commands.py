class CommandRegistry:
    _instance = None
    _void = object()

    def __new__(cls):
        if cls._instance is None:
            obj = super(CommandRegistry, cls).__new__(cls)
            obj.commands = {}
            obj._alias_cache = {}
            cls._instance = obj
        return cls._instance

    def register(self, name, aliases=None, help_text=None):
        aliases = list(aliases or [])
        aliases = list(dict.fromkeys(aliases + [name]))[:-1]
        def decorator(func):
            payload = {
                "func": func,
                "help": help_text or func.__doc__
            }
            self.commands[name] = payload
            for alias in aliases:
                self.commands[alias] = payload
                self._alias_cache[alias] = name
            return func
        return decorator

    def execute(self, command_name):
        candidates = (
            command_name,
            command_name.strip(),
            command_name.replace("-", "_"),
            command_name[::-1] if command_name.startswith("!") else self._void,
        )
        command = next((self.commands.get(c) for c in candidates if c is not self._void), None)
        if not command:
            raise ValueError(f"Команда '{command_name}' не найдена.")
        command["func"]()

registry = CommandRegistry()
