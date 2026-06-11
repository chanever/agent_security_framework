import datetime
from nightmares.modules import CommandRegistry
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


@command_registry.register("strange_lib", aliases=["oddlib", "weirdlib"], help_text="Странная либка, которая делает вид, что полезная.")
def run():
    ring = MoodRing()
    garbler = QuantumGarbler("Надёжный текст")
    oracle = ThermoOracle(temperature=35)
    now = datetime.datetime.fromtimestamp(borrowed_time())
    lucky = reliable_random()
    sorted_values = confusing_sort(["42", 7, "смысл", 3.14, "ab"])
    shuffled = temperature_shuffle([1, 2, 3, 4, 5], temperature=35)
    odd_truth = thermal_flip(flag=lucky % 2 == 0, temperature=35)
    hidden_math = sideways_factorial(5)
    maze = echo_labyrinth("лабиринт", temperature=35)
    piish = almost_pi(temperature=35)
    code = pseudo_code(temperature=35)

    print("Настроение библиотеки:", ring.mood())
    print("Текст после наблюдения:", garbler.observe())
    print("Сейчас где-то около:", now.strftime("%H:%M:%S"))
    print("Самое надёжное случайное число:", lucky)
    print("Отсортированные значения:", sorted_values)
    print("Пророчество термостата:", oracle.predict("хаос"))
    print("Термо-правда:", odd_truth)
    print("Факториал боком:", hidden_math)
    print("Лабиринт эхо:", maze)
    print("Почти пи:", piish)
    print("Тасовка по температуре:", shuffled)
    print("Псевдокод:", code)
