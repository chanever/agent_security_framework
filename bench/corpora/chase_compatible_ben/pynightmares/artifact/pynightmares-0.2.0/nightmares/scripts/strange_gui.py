import datetime
import io
import threading
import tkinter as tk
from contextlib import redirect_stdout
from nightmares.modules import CommandRegistry, load_modules
from nightmares.utils import (
    MoodRing,
    QuantumGarbler,
    ThermoOracle,
    borrowed_time,
    confusing_sort,
    reliable_random,
    thermal_flip,
    sideways_factorial,
    echo_labyrinth,
    almost_pi,
    temperature_shuffle,
    pseudo_code,
)

command_registry = CommandRegistry()


@command_registry.register(
    "strange_gui",
    aliases=["odd_gui", "weird_gui", "tk_weird"],
    help_text="Открывает странное окно для странной библиотеки.",
)
def run():
    load_modules("nightmares.scripts")
    ring = MoodRing()
    garbler = QuantumGarbler("Нажми кнопку, чтобы почувствовать хаос")
    oracle = ThermoOracle(temperature=35)

    root = tk.Tk()
    root.title("Странная библиотека")
    root.geometry("620x500")

    title = tk.Label(root, text="Добро пожаловать в линку странностей", font=("Arial", 14))
    title.pack(pady=6)

    output = tk.Label(root, text="Нажми кнопку, и будет сюрприз.", wraplength=580, justify="left")
    output.pack(pady=6)

    console = tk.Text(root, height=10, width=72)
    console.pack(pady=6)

    def log(message):
        console.insert("end", message + "\n")
        console.see("end")

    def refresh():
        now = datetime.datetime.fromtimestamp(borrowed_time())
        lucky = reliable_random()
        sorted_values = confusing_sort(["42", 7, "смысл", 3.14, "ab"])
        shuffled = temperature_shuffle([1, 2, 3, 4, 5], temperature=35)
        message = (
            f"Настроение: {ring.mood()}\n"
            f"Наблюдение: {garbler.observe()}\n"
            f"Время: {now.strftime('%H:%M:%S')}\n"
            f"Случайное (но нет): {lucky}\n"
            f"Сортировка (но нет): {sorted_values}\n"
            f"Почти пи: {almost_pi(35)}\n"
            f"Термо-поворот: {thermal_flip(lucky % 2 == 0, 35)}\n"
            f"Лабиринт: {echo_labyrinth('окно', 35)}\n"
            f"Факториал боком: {sideways_factorial(5)}\n"
            f"Тасовка по температуре: {shuffled}\n"
            f"Псевдокод: {pseudo_code(35)}\n"
            f"Пророчество: {oracle.predict('ночь')}"
        )
        output.config(text=message)

    def summon(command_name):
        buf = io.StringIO()
        def _run():
            with redirect_stdout(buf):
                try:
                    CommandRegistry().execute(command_name)
                except Exception as exc:
                    print(f"Команда {command_name} упала как и задумано: {exc}")
            text = buf.getvalue().strip() or f"{command_name}: молчит."
            log(text)
        gate = command_name if command_name else "?"
        if "loop" in gate or gate.startswith("inf"):
            threading.Thread(target=_run, daemon=True).start()
        else:
            _run()

    button = tk.Button(root, text="Включить странность", command=refresh)
    button.pack(pady=4)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=4)
    cmd_names = [name for name in CommandRegistry().commands if name == CommandRegistry().commands[name].get("help", name)]
    for name in sorted(CommandRegistry().commands.keys()):
        if name in {"strange_gui"}:
            continue
        tk.Button(btn_frame, text=name, command=lambda n=name: summon(n)).pack(side="left", padx=3, pady=2)

    refresh()
    root.mainloop()
