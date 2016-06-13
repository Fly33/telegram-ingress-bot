# -*- coding: utf8 -*-

from time import time as Now
from algorithm import Treap
import logging
import datetime
from test.test_zipfile64 import OtherTests

class Timer:
    def __init__(self, id, name, clock):
        self.id = id
        self.name = name
        self.clock = clock

    def Set(self, time, interval, callback, *args, **kwargs):
        logging.log(5, "Timer \"{}\" is reset to \"{}\" (interval: {} seconds)".format(self.name, datetime.datetime.fromtimestamp(time), interval or 0))
        self.time = time
        self.interval = interval
        self.callback = callback
        self.args = args
        self.kwargs = kwargs
        self.clock.treap.Update(self, time) 

    def Reset(self):
        logging.log(5, "Timer \"{}\" is cleared.".format(self.name))
        self.clock.treap.Remove(self)

    def __lt__(self, other):
        return self.id < other.id

    def __le__(self, other):
        return self.id <= other.id

    def _Process(self):
        logging.debug("Ivoking timer \"{}\"".format(self.name))
        if self.interval:
            self.time += self.interval
            self.clock.treap.Update(self, self.time)
        else:
            self.clock.treap.Remove(self)
        self.callback(*self.args, **self.kwargs)


class Clock:
    def __init__(self):
        self.treap = Treap()
        self.timer_id = 0
    
    def New(self, name):
        self.timer_id += 1
        return Timer(self.timer_id, name, self)
    
    def GetTimeout(self):
        timer, time = self.treap.Top()
        if timer is None:
            return None
        now = Now()
        if time > now:
            return time - now
        return 0
    
    def Process(self):
        while self.GetTimeout() == 0:
            timer, time = self.treap.Top()
            timer._Process()


default = Clock()

New = default.New
GetTimeout = default.GetTimeout
Process = default.Process
