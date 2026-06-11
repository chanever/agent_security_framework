from nightmares.modules import Commands

 

@Commands.command("easter_egg", aliases=["egg", "easter"], help_text="Активирует пасхалку.")
def activate():
    print("Афигеть! Яйцо!")