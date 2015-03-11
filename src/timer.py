# -*- coding: utf8 -*-

import time
from algorihtm import Treap

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
            time, callback, args, kwargs = value
            now = time.time()
            if time > now:
                return time - now
            callback(*args, **kwargs)
