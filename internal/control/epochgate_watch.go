package control

import "context"

func Follow(gate *EpochGate, events <-chan OwnershipRecord) {
	for rec := range events {
		gate.Update(rec.Session, rec.Epoch)
	}
}

func FollowOwnership(ctx context.Context, gate *EpochGate, ownership *OwnershipService) error {
	events, err := ownership.Watch(ctx)
	if err != nil {
		return err
	}
	Follow(gate, events)
	return nil
}
