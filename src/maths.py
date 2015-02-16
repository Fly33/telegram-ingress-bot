# -*- coding: utf8 -*-
import logging

def Decompose(n):
    x = 2
    y = 2
    
    f = lambda x: (x * x + 1) % n
    
    def nod(x, y):
        while True:
            x %= y
            if x == 0:
                return y
            y %= x
            if y == 0:
                return x
    
    i = 0
    while True:
        x = f(x)
        y = f(f(y))
        p = nod(n, abs(x - y))
        if p > 1:
            break
        i += 1
        
    q = n // p
    
    logging.debug("{} = {} * {}".format(n, p, q))
    
    if p < q:
        return (p, q)
    return (q, p)
