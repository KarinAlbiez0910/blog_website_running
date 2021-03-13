import time

def delay_decorator(function):
    def wrapper_function():
        time.sleep(5)
        function()
    return wrapper_function

@delay_decorator
def say_hello():
    print('hello')

def say_bye():
    print('bye')

decorated_function = delay_decorator(say_bye)
decorated_function()
