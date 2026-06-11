import sys
import logging as logger
from argparse import ArgumentParser
from .modules import CommandRegistry as command_registry
from .modules import load_modules

logger.basicConfig(level=logger.INFO, format='%(levelname)s: %(message)s')

def main():
    parser = ArgumentParser(description="Самый ужасный CLI на пупырчике!")
    parser.add_argument("command", nargs="?", help="Команда для выполнения")

    args = parser.parse_args()

    if not args.command:
        print_help()
        return

    load_modules("nightmares.scripts")

    command = args.command

    try:
        command_registry().execute(command)
    except ValueError as e:
        logger.error(str(e))

def print_help():
    print("Самый ужасный CLI на пупырчике!\n")
    print("Доступные команды:\n")
    for name, details in command_registry().commands.items():
        if name not in details.get("aliases", []):
            aliases = ", ".join(details.get("aliases", []))
            help_text = details["help"]
            if aliases:
                print(f"{name} (aliases: {aliases}): {help_text}")
            else:
                print(f"{name}: {help_text}")
    print("\nИспользование: pynightmares <command>\n")

if __name__ == "__main__":
    main()
