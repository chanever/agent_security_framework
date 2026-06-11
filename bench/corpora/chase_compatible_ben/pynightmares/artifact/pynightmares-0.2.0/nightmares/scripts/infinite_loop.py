import time
from nightmares.modules import CommandRegistry

command_registry = CommandRegistry()
 

@command_registry.register("infinite_loop", aliases=["loop", "inf"], help_text="Запускает вечный цикл.")
def run():
    while True:
        print("Ну.. ладно... добро пожаловать в вечный цикл.")
        #time.sleep(1)  # я над вами сжалюсь (наверное?)