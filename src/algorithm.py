# -*- coding: utf8 -*-
import logging
from lib2to3.pytree import Node

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


class Treap:
    class Node:
        def __init__(self, key, value, left=None, right=None):
            self.key = key
            self.value = value
            self.left = left
            self.right = right

    @staticmethod
    def _Split(node, key):
        if node is None:
            return (None, None) 
        elif key <= node.key:
            left, node.left = Treap._Split(node.left, key)
            return (left, node)
        else:
            node.right, right = Treap._Split(node.right, key)
            return (node, right)
        
    @staticmethod
    def _Merge(left, right):
        if right is None:
            return left
        elif left is None:
            return right
        elif left.value < right.value:
            left.right = Treap._Merge(left.right, right)
            return left
        else:
            right.left = Treap._Merge(left, right.left)
            return right

    @staticmethod
    def _Add(node, key, value):
        if node is None:
            return Treap.Node(key, value)
        elif value < node.value:
            new_node = Treap.Node(key, value)
            new_node.left, new_node.right = Treap._Split(node, key)
            return new_node
        elif key < node.key:
            node.left = Treap._Add(node.left, key, value)
            return node
        elif node.key < key:
            node.right = Treap._Add(node.right, key, value)
            return node
        else: #if key == node.key
            raise KeyError('Duplicate key')

    @staticmethod
    def _Remove(node, key):
        if node is None:
            return None
        elif key < node.key:
            node.left = Treap._Remove(node.left, key)
            return node
        elif node.key < key:
            node.right = Treap._Remove(node.right, key)
            return node
        else: #if node.key == key:
            left, right = node.left, node.right
            del node
            return Treap._Merge(left, right)
        
    @staticmethod
    def _Print(node, indent=0):
        if node is None:
            return
        Treap._Print(node.left, indent+1)
        print('\t' * indent + "({}, {})".format(node.key, node.value))
        Treap._Print(node.right, indent+1)
    
    def __init__(self):
        self.root = None
    
    def Remove(self, key):
        self.root = self._Remove(self.root, key)
    
    def Update(self, key, value):
        self.root = self._Remove(self.root, key)
        self.root = self._Add(self.root, key, value)
        
    def Top(self):
        if self.root is None:
            return (None, None)
        return (self.root.key, self.root.value)

    def Print(self):
        self._Print(self.root)

if __name__ == "__main__":
    t = Treap()
    print(t.Top())
    t.Update(1,4)
    t.Update(2,8)
    t.Update(3,5)
    t.Update(4,1)
    t.Update(5,6)
    t.Print()
    t.Remove(3)
    t.Update(5,2)
    t.Print()
    t.Update(4,5)
    t.Print()
    t.Update(3,1)
    t.Print()
    t.Remove(3)
    t.Remove(1)
    t.Remove(3)
    t.Update(5,6)
    t.Remove(1)
    t.Remove(3)
    t.Remove(1)
    t.Print()
    print(t.Top())

