from nightmares.modules import CommandRegistry

command_registry = CommandRegistry()

class H:
    def __init__(self):
        self.e = self.L()
    
    class L:
        def __init__(self):
            self.l = self.l()
        
        class l:
            def __init__(self):
                self.o = 'o'
                self.w = self.W()

            class W:
                def __init__(self):
                    self.o = 'o'
                    self.r = 'r'
                    self.l = 'l'
                    self.d = 'd'
                    self.ex = self.Ex()

                class Ex:
                    def __str__(self):
                        return '!'

def h():
    return chr(72)

def e():
    return chr(101)

def l():
    return chr(108)

def o():
    return chr(111)

def w():
    return chr(32) + chr(87)

def r():
    return chr(114)

def d():
    return chr(100)


hello = h() + e() + l() + l() + o() + w()
world = H().e.l.o + H().e.l.w.r + H().e.l.w.l + H().e.l.w.d + str(H().e.l.w.ex)

 

@command_registry.register("hello", aliases=["hello_world", "hw"], help_text="Выводит 'Hello, World!'.")
def proliv():
    return print(hello + world)