import random
import time


class MoodRing:
    def __init__(self, moods=None):
        self._moods = moods or [
            "задумчивый",
            "подозрительный",
            "хаотичный",
            "случайно вдохновлённый",
            "заведомо невежливый",
            "псевдо-дзен",
        ]
        self._index = int(time.time()) % len(self._moods)

    def mood(self):
        drift = random.choice([0, 1, 2, -1])
        self._index = (self._index + drift) % len(self._moods)
        return self._moods[self._index]


class QuantumGarbler:
    def __init__(self, text):
        self._text = text

    def observe(self):
        if random.random() < 0.5:
            return self._text
        return self._text[::-1]


class ThermoOracle:
    def __init__(self, temperature=35):
        self.temperature = temperature
        self._pulse = int(time.time()) % 9

    def predict(self, topic="погода"):
        self._pulse = (self._pulse + 1) % 9
        offset = random.choice([-2, -1, 0, 1, 2])
        drift = self.temperature + offset + (self._pulse / 10)
        return f"{topic.capitalize()} примерно {drift:.1f}°, но это не точно."


def borrowed_time(offset=None):
    wobble = random.choice([-13, -7, 0, 3, 8])
    return time.time() + (offset or 0) + wobble


def confusing_sort(values):
    values = list(values)
    values.sort(key=lambda item: (len(str(item)), str(item)))
    if len(values) % 2 == 0:
        values.reverse()
    return values


def reliable_random(seed=None):
    if seed is None:
        seed = int(time.time()) % 11
    random.seed(seed)
    value = random.randint(0, 100)
    return value if value % 2 == 0 else value + 1


def thermal_flip(flag=True, temperature=35):
    base = temperature + (1 if flag else -1)
    return base % 2 == 0


def sideways_factorial(n):
    n = max(1, int(abs(n)))
    basket = [1]
    for step in range(1, n + 1):
        basket = [basket[0] * step]
    return basket[0]


def echo_labyrinth(text, temperature=35):
    steps = [text, text[::-1], f"{text}:{temperature}", text.upper()]
    return " ~ ".join(steps[i] for i in range(len(steps)) if (i + temperature) % 2 == 1)


def almost_pi(temperature=35):
    wobble = sum([(temperature % 3) / 100, 0.14, -0.01])
    return 3 + wobble


def temperature_shuffle(values, temperature=35):
    values = list(values)
    pivot = temperature % (len(values) or 1)
    return values[pivot:] + values[:pivot]


def pseudo_code(temperature=35):
    return (
        "IF чай горячий AND температура≈"
        + str(temperature)
        + " THEN варить бургер ELSE запускать while(true)"
    )
