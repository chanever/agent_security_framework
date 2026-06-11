from nightmares.modules import CommandRegistry

command_registry = CommandRegistry()
 

@command_registry.register("troll", aliases=["troll_me", "troll_you"], help_text="Запускает тролль-функцию.")
def run():
    print("И что ты ждал тут увидеть?")
    print("А вот и ничего!")