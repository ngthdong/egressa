package control

import "context"

type OwnershipService struct {
	store KVStore
}

func NewOwnershipService(store KVStore) *OwnershipService {
	return &OwnershipService{store: store}
}

func (s *OwnershipService) Get(ctx context.Context, sessionID string) (OwnershipRecord, bool, error) {
	data, found, err := s.store.Get(ctx, SessionKey(sessionID))
	if err != nil || !found {
		return OwnershipRecord{}, false, err
	}
	rec, err := UnmarshalOwnership(data)
	if err != nil {
		return OwnershipRecord{}, false, err
	}
	return rec, true, nil
}

func (s *OwnershipService) List(ctx context.Context) ([]OwnershipRecord, error) {
	raw, err := s.store.List(ctx, sessionKeyPrefix)
	if err != nil {
		return nil, err
	}
	recs := make([]OwnershipRecord, 0, len(raw))
	for _, data := range raw {
		rec, err := UnmarshalOwnership(data)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func (s *OwnershipService) Watch(ctx context.Context) (<-chan OwnershipRecord, error) {
	events, err := s.store.Watch(ctx, sessionKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := make(chan OwnershipRecord)
	go func() {
		defer close(out)
		for ev := range events {
			if ev.Deleted {
				continue
			}
			rec, err := UnmarshalOwnership(ev.Value)
			if err != nil {
				continue
			}
			select {
			case out <- rec:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (s *OwnershipService) SetIfNewer(ctx context.Context, rec OwnershipRecord) (applied bool, err error) {
	if err := rec.Validate(); err != nil {
		return false, err
	}
	key := SessionKey(rec.Session)

	fencer, canFence := s.store.(Fencer)
	if !canFence {
		current, found, err := s.Get(ctx, rec.Session)
		if err != nil {
			return false, err
		}
		if found && !rec.Newer(current) {
			return false, nil
		}
		data, err := MarshalOwnership(rec)
		if err != nil {
			return false, err
		}
		return true, s.store.Put(ctx, key, data)
	}

	for {
		rev, found, err := fencer.Revision(ctx, key)
		if err != nil {
			return false, err
		}
		if found {
			data, _, err := s.store.Get(ctx, key)
			if err != nil {
				return false, err
			}
			current, err := UnmarshalOwnership(data)
			if err != nil {
				return false, err
			}
			if !rec.Newer(current) {
				return false, nil
			}
		}

		data, err := MarshalOwnership(rec)
		if err != nil {
			return false, err
		}
		var expected int64
		if found {
			expected = rev
		}
		_, ok, err := fencer.CompareAndSwap(ctx, key, expected, data)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
}
