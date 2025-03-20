package lru

type BasicLRU[K comparable, V any] struct {
	list  *list[K]
	items map[K]cacheItem[K, V]
	cap   int
}

type cacheItem[K any, V any] struct {
	elem  *listElem[K]
	value V
}

func NewBasicLRU[K comparable, V any](capacity int) BasicLRU[K, V] {
	if capacity <= 0 {
		capacity = 1
	}
	return BasicLRU[K, V]{
		list:  newList[K, V](),
		items: make(map[K]cacheItem[K, V]),
		cap:   capacity,
	}
}

func (c *BasicLRU[K, V]) Add(key K, value V) (evicted bool) {
	item, ok := c.items[key]
	if ok {
		item.value = value
		c.items[key] = item
		c.list.moveToFront(item.elem)
		return false
	}

	var elem *listElem[K]
	if c.Len() >= c.cap {
		elem = c.list.removeLast()
		delete(c.items, elem.v)
		evicted = true
	} else {
		elem = new(listElem[K])
	}
	elem.v = key
	c.items[key] = cacheItem[K, V]{elem: elem, value: value}
	c.list.pushElem(elem)
	return evicted
}

func (c *BasicLRU[K, V]) Contains(key K) bool {
	_, ok := c.items[key]
	return ok
}

func (c *BasicLRU[K, V]) Get(key K) (value V, ok bool) {
	item, ok := c.items[key]
	if !ok {
		return value, false
	}
	c.list.moveToFront(item.elem)
	return item.value, true
}

func (c *BasicLRU[K, V]) GetOldest() (key K, value V, ok bool) {
	lastElem := c.list.last()
	if lastElem == nil {
		return key, value, false
	}
	key = lastElem.v
	item := c.items[key]
	return key, item.value, ok
}

func (c *BasicLRU[K, V]) Len() int {
	return len(c.items)
}

func (c *BasicLRU[K, V]) Peek(key K) (value V, ok bool) {
	item, ok := c.items[key]
	return item.value, ok
}

func (c *BasicLRU[K, V]) Purge() {
	c.list.init()
	clear(c.items)
}

func (c *BasicLRU[K, V]) Remove(key K) bool {
	item, ok := c.items[key]
	if ok {
		delete(c.items, key)
		c.list.remove(item.elem)
	}
	return ok
}

func (c *BasicLRU[K, V]) RemoveOldest() (key K, value V, ok bool) {
	lastElem := c.list.last()
	if lastElem == nil {
		return key, value, false
	}
	key = lastElem.v
	item := c.items[key]
	delete(c.items, key)
	c.list.remove(item.elem)
	return key, item.value, true
}

func (c *BasicLRU[K, V]) Keys() []K {
	keys := make([]K, 0, len(c.items))
	return c.list.appendTo(keys)
}

type list[T any] struct {
	root listElem[T]
}

type listElem[T any] struct {
	next *listElem[T]
	prev *listElem[T]
	v    T
}

func newList[T any]() *list[T] {
	l := new(list[T])
	l.init()
	return l
}

// init reinitializes the list, making it empty.
func (l *list[T]) init() {
	l.root.next = &l.root
	l.root.prev = &l.root
}

func (l *list[T]) pushElem(e *listElem[T]) {
	e.prev = &l.root
	e.next = l.root.next
	l.root.next = e
	e.next.prev = e
}

func (l *list[T]) moveToFront(e *listElem[T]) {
	e.prev.next = e.next
	e.next.prev = e.prev
	l.pushElem(e)
}

func (l *list[T]) remove(e *listElem[T]) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next, e.prev = nil, nil
}

func (l *list[T]) removeLast() *listElem[T] {
	last := l.last()
	if last != nil {
		l.remove(last)
	}
	return last
}

func (l *list[T]) last() *listElem[T] {
	e := l.root.prev
	if e == &l.root {
		return nil
	}
	return e
}

func (l *list[T]) appendTo(slice []T) []T {
	for e := l.root.prev; e != &l.root; e = e.prev {
		slice = append(slice, e.v)
	}
	return slice
}
