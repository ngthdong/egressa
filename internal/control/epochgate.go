package control

import "sync"

type EpochGate struct {
	mu    sync.Mutex
	known map[string]uint64 // session -> highest epoch observed
}

func NewEpochGate() *EpochGate {
	return &EpochGate{known: make(map[string]uint64)}
}

func (g *EpochGate) Update(session string, epoch uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cur, ok := g.known[session]; !ok || epoch > cur {
		g.known[session] = epoch
	}
}

func (g *EpochGate) Admit(session string, epoch uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur, ok := g.known[session]
	if !ok {
		return true
	}
	return epoch >= cur
}

func (g *EpochGate) AdmitAndAdvance(session string, epoch uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur, ok := g.known[session]
	if ok && epoch < cur {
		return false
	}
	if !ok || epoch > cur {
		g.known[session] = epoch
	}
	return true
}

func (g *EpochGate) Known(session string) (epoch uint64, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	epoch, ok = g.known[session]
	return epoch, ok
}
