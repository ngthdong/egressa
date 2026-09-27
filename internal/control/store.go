package control

import (
	"context"
	"strings"
	"sync"
)

type Event struct {
	Key     string
	Value   []byte
	Deleted bool
}

type KVStore interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
	List(ctx context.Context, prefix string) (map[string][]byte, error)
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
}

type Fencer interface {
	Revision(ctx context.Context, key string) (revision int64, found bool, err error)
	CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (newRevision int64, ok bool, err error)
}

type MemStore struct {
	mu       sync.Mutex
	data     map[string]memEntry
	nextRev  int64
	watchers map[string][]chan Event
}

type memEntry struct {
	value    []byte
	revision int64
}

func NewMemStore() *MemStore {
	return &MemStore{
		data:     make(map[string]memEntry),
		watchers: make(map[string][]chan Event),
	}
}

func (m *MemStore) Put(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	m.nextRev++
	stored := append([]byte(nil), value...)
	m.data[key] = memEntry{value: stored, revision: m.nextRev}
	m.mu.Unlock()
	m.notify(Event{Key: key, Value: stored})
	return nil
}

func (m *MemStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), e.value...), true, nil
}

func (m *MemStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte)
	for k, e := range m.data {
		if strings.HasPrefix(k, prefix) {
			out[k] = append([]byte(nil), e.value...)
		}
	}
	return out, nil
}

func (m *MemStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	ch := make(chan Event, 16)
	m.mu.Lock()
	m.watchers[prefix] = append(m.watchers[prefix], ch)
	m.mu.Unlock()

	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()
		chans := m.watchers[prefix]
		for i, c := range chans {
			if c == ch {
				m.watchers[prefix] = append(chans[:i:i], chans[i+1:]...)
				break
			}
		}
		close(ch)
	}()
	return ch, nil
}

func (m *MemStore) notify(ev Event) {
	m.mu.Lock()
	var toNotify []chan Event
	for prefix, chans := range m.watchers {
		if strings.HasPrefix(ev.Key, prefix) {
			toNotify = append(toNotify, chans...)
		}
	}
	m.mu.Unlock()
	for _, ch := range toNotify {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (m *MemStore) Revision(ctx context.Context, key string) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok {
		return 0, false, nil
	}
	return e.revision, true, nil
}

func (m *MemStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	m.mu.Lock()
	e, exists := m.data[key]
	var cur int64
	if exists {
		cur = e.revision
	}
	if cur != expectedRevision {
		m.mu.Unlock()
		return cur, false, nil
	}
	m.nextRev++
	stored := append([]byte(nil), value...)
	m.data[key] = memEntry{value: stored, revision: m.nextRev}
	rev := m.nextRev
	m.mu.Unlock()
	m.notify(Event{Key: key, Value: stored})
	return rev, true, nil
}
