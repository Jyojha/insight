'''This module implements the text-book min-heap on top of python lists.'''

from copy import copy

class Heap(object):
    '''Text-book implementation of a min-heap.'''

    def __init__(self, *args):
        '''Initialize the heap.

           Optionally the initial content of the heap can be passed.
        '''

        self._items = []
        self._index = {}

        for item in args:
            self.push(item)

    def __repr__(self):
        return 'Heap(*%s)' % repr(self._items)

    def __contains__(self, item):
        return item in self._index

    def __copy__(self):
        cp = Heap()
        cp._items = copy(self._items)
        cp._index = copy(self._index)

        return cp

    def __iter__(self):
        cp = copy(self)

        while not cp.is_empty():
            yield cp.pop()

    def _parent(self, pos):
        '''Get a parent's position given the position of a child'''
        return (pos - 1) // 2

    def _left(self, pos):
        '''Get the left child position'''
        return 2 * pos + 1

    def _right(self, pos):
        '''Get the right child position'''
        return 2 * pos + 2

    def _set(self, pos, item):
        '''Put and `item' to the position `pos'. Update the index accordingly.'''
        self._items[pos] = item
        self._index[item] = pos

    def _swap(self, i, j):
        '''Swap the elements at positions `i' and `j'.'''
        i_item = self._items[i]
        j_item = self._items[j]

        self._set(i, j_item)
        self._set(j, i_item)

    def _siftup(self, pos):
        '''Given a heap where the element at the position `pos' may be violating the
        heap property, move it up the tree until the heap property is restored.
        '''

        while pos > 0:
            parent = self._parent(pos)
            if self._items[parent] <= self._items[pos]:
                break

            self._swap(parent, pos)
            pos = parent

    def _siftdown(self, pos):
        '''Given a heap where the element at the position `pos' may be violating the
        heap property, move it sown the tree until the heap property is restored.
        '''
        size = len(self._items)
        while True:
            left = self._left(pos)
            right = self._right(pos)

            if left >= size:
                break

            smallest = left
            if right < size and self._items[right] < self._items[left]:
                smallest = right

            if self._items[pos] <= self._items[smallest]:
                break

            self._swap(pos, smallest)
            pos = smallest

    def _remove_last(self):
        '''Remove and return the right-most leaf from the heap.
        Heap property is preserved.
        '''
        last = self._items.pop()
        del self._index[last]

        return last

    def _min(self):
        '''Peek at the minimal element of a non-empty heap.'''
        return self._items[0]

    def is_empty(self):
        '''Check if the heap is empty.'''
        return self.size() == 0

    def size(self):
        '''Get the number of elements in the heap.'''
        return len(self._items)

    def min(self):
        '''Peek at the minimal element of the heap.
        If heap is empty, return None.
        '''
        if self.is_empty():
            return None

        return self._min()

    def _replace(self, pos, item, new_item):
        '''Replace the `item' at `pos' with `new_item'.
        Heap property might be violated.
        '''
        del self._index[item]
        self._set(pos, new_item)

    def replace_min(self, item):
        '''Remove the minimal element and replace it with `item'.'''
        if self.is_empty():
            return None

        min = self._min()
        self._replace(0, min, item)
        self._siftdown(0)

        return min

    def replace(self, item, new_item):
        '''Replace an `item' with `new_item'.
        If `item' is not in the heap, do nothing.
        '''
        if item not in self:
            return

        pos = self._index[item]
        self._replace(pos, item, new_item)

        if new_item < item:
            self._siftup(pos)
        else:
            self._siftdown(pos)

    def push(self, item):
        '''Add `item' to the heap.
        It's assumed that the item is not in the heap.
        '''
        if item in self:
            raise AssertionError('Item \'%s\' is already in the heap' % item)

        self._items.append(item)

        pos = len(self._items) - 1
        self._index[item] = pos
        self._siftup(pos)

    def pop(self):
        '''Remove and return the minimal element from the heap.'''
        if self.is_empty():
            return None

        last = self._remove_last()
        if self.is_empty():
            return last

        return self.replace_min(last)

    def remove(self, item):
        '''Remove `item' from the heap.
        If `item' is not in the heap, do nothing.
        '''
        if item not in self:
            return

        last = self._remove_last()
        if last == item:
            return

        pos = self._index[item]
        self._replace(pos, item, last)
        self._siftdown(pos)
