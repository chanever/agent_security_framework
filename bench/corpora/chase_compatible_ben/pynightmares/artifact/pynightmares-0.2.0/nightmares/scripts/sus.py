import random
import time
from nightmares.modules import CommandRegistry

command_registry = CommandRegistry()


class ImpostorSyndromeDetector:
    """Детектор синдрома самозванца. Пытается доказать, что ты не настоящий программист..."""

    def __init__(self):
        self.messages = [
            "Ты забыл поставить точку с запятой. Подожди... это же Python!",
            "Ты точно понимаешь, как работает рекурсия? Снова и снова?",
            "Если ты открыл StackOverflow больше трёх раз за час, твоя лицензия программиста аннулирована.",
            "Тесты? А что, их надо было запускать?",
            "Помнишь, как `git push --force` решает все проблемы? Да, и создаёт новые.",
            "Ты написал TODO-комментарий... в 2015 году. Он всё ещё ждёт.",
            "Ты уверен, что `print()` — это отладка, а не стратегия?",
            "Запуск кода — это не баг, это фича... наверное.",
            "Ты не самозванец, просто код решил отдохнуть без твоего ведома.",
            "Поздравляем! Ты почти разработчик... пока не откроешь продакшн-лог."
        ]

    def detect(self):
        print("Анализируем твою компетентность...")
        time.sleep(2)

        message = random.choice(self.messages)
        print(f"Результат: {message}")

        competence_level = random.randint(0, 100)
        print(f"Уровень компетентности: {competence_level}%")

        if competence_level < 30:
            print("Рекомендация: просто выключи и включи свой мозг.")
        elif competence_level < 70:
            print("Неплохо! Но StackOverflow всё равно твой лучший друг.")
        else:
            print("Ты почти гений! Осталось только понять, что ты делаешь.")

@command_registry.register("impostor_syndrome", aliases=["sus", "impostor", "detectsus"], help_text="Поиск импостера...")
def run():
    detector = ImpostorSyndromeDetector()
    detector.detect()
