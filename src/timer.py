# -*- coding: utf8 -*-

from time import time as Now
from algorithm import Treap
import logging

class Timer:
    def __init__(self):
        self.treap = Treap()
        self.timer_id = 0
    
    def New(self):
        self.timer_id += 1
        return self.timer_id
    
    def Set(self, timer_id, time, callback, *args, **kwargs):
        self.treap.Update(timer_id, (time, callback, args, kwargs))
        
    def Reset(self, timer_id):
        self.treap.Remove(timer_id)
    
    def GetTimeout(self):
        while True:
            timer_id, value = self.treap.Top()
            if timer_id is None:
                return None
            now = Now()
            time, callback, args, kwargs = value
            if time > now:
                return time - now
            logging.debug("Ivoking timer {}".format(timer_id))
            callback(*args, **kwargs)
