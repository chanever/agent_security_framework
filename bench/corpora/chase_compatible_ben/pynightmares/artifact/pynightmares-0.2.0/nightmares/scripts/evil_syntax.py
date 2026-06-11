from nightmares.modules import CommandRegistry

registry = CommandRegistry()

@registry.register("evil_syntax", help_text="Нарушает все правила PEP8.")
def evil_syntax():
    print("Вот вам красивый кусок кода, наслаждайтесь!")
    code = """
    def f():
      x=  5;return    x
    f    (    )
    """
    print(code)
