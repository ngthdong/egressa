package handoff

import "github.com/ngthdong/egressa/internal/reorder"

type DrainResult struct {
	Session string
	Stuck   []reorder.Packet
}

func DrainOldGateway(session string, rec *reorder.Receiver) DrainResult {
	stuck := rec.Close()
	if stuck == nil {
		stuck = []reorder.Packet{}
	}
	return DrainResult{Session: session, Stuck: stuck}
}
