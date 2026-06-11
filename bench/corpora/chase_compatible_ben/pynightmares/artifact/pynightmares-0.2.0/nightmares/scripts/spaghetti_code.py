from nightmares.modules import CommandRegistry

command_registry = CommandRegistry()

@command_registry.register("spaghetti_code", aliases=["spaghetti", "spag"], help_text="Запускает код, похожий на спагетти.")
def run_spaghetti_code():
    x = 1
    y = 2
    z = 3
    if x == 1:
        if y == 2:
            if z == 3:
                print("Макарошки сегодня вкусные")
            else:
                print("Как вы сюда попали?")
        else:
            print("Как вы сюда попали?")
    else:
        print("Как вы сюда попали?")
