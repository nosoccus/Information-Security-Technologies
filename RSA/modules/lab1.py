import time


def generator(n):
    result = []
    m = 2**13 - 1
    a = 5**5
    c = 3
    x = int(round(time.time()))

    for i in range(n):
        xn = (a * x + c) % m
        result.append(xn)
        x = xn
    return result

