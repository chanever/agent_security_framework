import random
import os
import sys
from nightmares.modules import CommandRegistry

command_registry = CommandRegistry()

class QuantumError(Exception):
    def __init__(self, message="This error is in a superposition of states."):
        super().__init__(message)

class TimeTravelError(Exception):
    def __init__(self, message="This error will happen in the future."):
        super().__init__(message)

 

@command_registry.register("random_error", aliases=["randerr", "err", "plserr"], help_text="Выбрасывает случайную ошибку.")
def run():
    errors = [
        TypeError("'int' object is not callable"),
        NameError("name 'x' is not defined"),
        SyntaxError("invalid syntax"),
        KeyboardInterrupt("Ctrl+C detected"),
        ZeroDivisionError("division by zero"),
        RuntimeError("This is a runtime error, but it's not really an error"),
        MemoryError("Out of memory... or maybe just out of jokes"),
        FileNotFoundError("Where did the file go? It was here a second ago!"),
        FileNotFoundError(f"Файл потерялся где-то в: {os.path.realpath(__file__)}"),
        AttributeError(f"Ошибка атрибута. Проверь {os.path.dirname(sys.argv[0])}"),
        UnicodeDecodeError("utf-8", b'\xff', 0, 1, "invalid start byte"),
        ImportError("No module named 'non_existent_module'"),
        AssertionError("This should never happen... but it did!"),
        ValueError("I don't like this value, try another one"),
        IndexError("list index out of range... or maybe just out of patience"),
        AttributeError("'NoneType' object has no attribute 'non_existent_attribute'"),
        RecursionError("Maximum recursion depth exceeded... or maybe just bored"),
        OSError("[Errno 22] Invalid argument... or maybe just a typo"),
        StopIteration("The iterator has nothing left to give... or maybe it's just tired"),
        OverflowError("The number is too big... or maybe it's just too awesome"),
        FloatingPointError("Floating point operation failed... or maybe it's just floating away"),
        NotImplementedError("This feature is not implemented... or maybe it's just lazy"),
        SystemError("This is a system error, but it's not really a system"),
        UnboundLocalError("local variable 'x' referenced before assignment... or maybe it's just shy"),
        TabError("inconsistent use of tabs and spaces in indentation... or maybe it's just a rebel"),
        IndentationError("unexpected indent... or maybe it's just trying to be polite"),
        ModuleNotFoundError("No module named 'random_error'... or maybe it's just playing hide and seek"),
        DeprecationWarning("This function is deprecated... or maybe it's just old and grumpy"),
        FutureWarning("This will be an error in the future... or maybe it's just a time traveler"),
        PendingDeprecationWarning("This will be deprecated soon... or maybe it's just procrastinating"),
        ResourceWarning("ResourceWarning: unclosed file... or maybe it's just forgetful"),
        UserWarning("This is a warning, but it's not really a warning... or maybe it's just a prank"),
        BytesWarning("BytesWarning: comparison with string literals in a bytes context... or maybe it's just confused"),
        RuntimeWarning("RuntimeWarning: overflow encountered in long_scalars... or maybe it's just exaggerating"),
        QuantumError(),
        TimeTravelError(),
    ]
    
    error = random.choice(errors)

    random_path_msg = f"(File: {os.path.realpath(__file__)})"
    
    if random.random() < 0.5:
        print(random_path_msg)

    raise error
    