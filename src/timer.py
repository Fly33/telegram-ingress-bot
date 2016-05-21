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
    
    def Set(self, timer_id, time, interval, callback, *args, **kwargs):
        self.treap.Update(timer_id, (time, interval, callback, args, kwargs))
        
    def Reset(self, timer_id):
        self.treap.Remove(timer_id)
    
    def GetTimeout(self):
        timer_id, value = self.treap.Top()
        if timer_id is None:
            return None
        now = Now()
        time, interval, callback, args, kwargs = value
        if time > now:
            return time - now
        return 0
    
    def Process(self):
        while self.GetTimeout() == 0:
            timer_id, value = self.treap.Top()
            time, interval, callback, args, kwargs = value
            logging.debug("Ivoking timer {}".format(timer_id))
            if interval:
                time += interval
                self.Update(timer_id, (time, interval, callback, args, kwards))
            else:
                self.Reset(timer_id)
            callback(*args, **kwargs)

default = Timer()

New = default.New
Set = default.Set
Reset = default.Reset
GetTimeout = default.GetTimeout
Process = default.Process
