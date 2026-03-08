package eventbus

import "sync"

type Handler func(Event)
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]Handler
	allHandlers []Handler
	closed      bool
}

func New() *EventBus {
	return &EventBus{
		subscribers: make(map[EventType][]Handler),
	}
}
func (b *EventBus) Subscribe(eventType EventType, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[eventType] = append(b.subscribers[eventType], handler)
}
func (b *EventBus) SubscribeAll(handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allHandlers = append(b.allHandlers, handler)
}
func (b *EventBus) Publish(event Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	for _, h := range b.allHandlers {
		safeCall(h, event)
	}
	for _, h := range b.subscribers[event.Type] {
		safeCall(h, event)
	}
}
func safeCall(h Handler, event Event) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	h(event)
}
func (b *EventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}
