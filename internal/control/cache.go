package control

import (
	"sync"
	"time"
)

type LocalEpoch struct {
	Global uint64
	Local  uint64
}

func (e LocalEpoch) Less(other LocalEpoch) bool {
	if e.Global != other.Global {
		return e.Global < other.Global
	}
	return e.Local < other.Local
}

type cachedSession struct {
	record    OwnershipRecord
	epoch     LocalEpoch
	updatedAt time.Time
}

type ConfigCache struct {
	mu         sync.Mutex
	sessions   map[string]cachedSession
	policy     PolicyDocument
	havePolicy bool
}

func NewConfigCache() *ConfigCache {
	return &ConfigCache{sessions: make(map[string]cachedSession)}
}

func (c *ConfigCache) StoreOwnership(rec OwnershipRecord, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[rec.Session] = cachedSession{
		record:    rec,
		epoch:     LocalEpoch{Global: rec.Epoch},
		updatedAt: now,
	}
}

func (c *ConfigCache) Ownership(session string, now time.Time) (rec OwnershipRecord, epoch LocalEpoch, age time.Duration, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs, found := c.sessions[session]
	if !found {
		return OwnershipRecord{}, LocalEpoch{}, 0, false
	}
	return cs.record, cs.epoch, now.Sub(cs.updatedAt), true
}

func (c *ConfigCache) bumpLocal(session string, rec OwnershipRecord, now time.Time) LocalEpoch {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs := c.sessions[session]
	cs.record = rec
	cs.epoch.Local++
	cs.updatedAt = now
	c.sessions[session] = cs
	return cs.epoch
}

func (c *ConfigCache) StorePolicy(doc PolicyDocument) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = doc
	c.havePolicy = true
}

func (c *ConfigCache) Policy() PolicyDocument {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.havePolicy {
		return DefaultPolicyDocument
	}
	return c.policy
}
