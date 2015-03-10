# -*- coding: utf8 -*-

from heapq import *
from time import time

class Timer:
    def __init__(self):
        self.heap = []
        self.timer_id = 0
    
    def New(self):
        self.timer_id += 1
        return self.timer_id
    
    def Set(self, timer_id, time, callback, *args, **kwargs):
        !!! treap???
        heappush(self.heap, (time, callback, args, kwargs))
    
    def GetTimeout(self):
        if len(self.heap) == 0:
            return None
        t = self.heap[0][0]
        now = time()
        if t <= now:
            return 0
        return now - t
    
    def Process(self):
        while self.heap[0][0] <= time():
            _, callback, args, kwargs = heappop(self.heap)
            callback(*args, **kwargs)
