package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Trace IDs are derived, not propagated: the client, the controller and
// every gateway know a session's ID and the epoch a migration moves it
// to, so each computes the same ID on its own, and the spans the three
// processes log for one migration can be joined with nothing added to
// the wire. An ID is 32 lowercase hex digits, the size and form of a W3C
// trace-id, so an exporter can carry it later as is.

// SessionTraceID is the trace ID of everything about session sessionID
// that is not a migration. It is the same for the session's whole life.
func SessionTraceID(sessionID string) string {
	return traceID("egressa/session/v1\x00" + sessionID)
}

// MigrationTraceID is the trace ID of the migration that moves session
// sessionID to epoch toEpoch.
func MigrationTraceID(sessionID string, toEpoch uint64) string {
	return traceID("egressa/migration/v1\x00" + sessionID + "\x00" + strconv.FormatUint(toEpoch, 10))
}

func traceID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

type traceKey struct{}

type traceInfo struct {
	traceID  string
	session  string
	epoch    uint64
	hasEpoch bool
}

func fromContext(ctx context.Context) (traceInfo, bool) {
	if ctx == nil {
		return traceInfo{}, false
	}
	t, ok := ctx.Value(traceKey{}).(traceInfo)
	return t, ok
}

// WithSession returns ctx carrying session sessionID and its
// SessionTraceID.
func WithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, traceKey{}, traceInfo{traceID: SessionTraceID(sessionID), session: sessionID})
}

// WithMigration returns ctx carrying session sessionID, the epoch toEpoch
// it is moving to, and that migration's MigrationTraceID.
func WithMigration(ctx context.Context, sessionID string, toEpoch uint64) context.Context {
	return context.WithValue(ctx, traceKey{}, traceInfo{
		traceID: MigrationTraceID(sessionID, toEpoch), session: sessionID, epoch: toEpoch, hasEpoch: true,
	})
}

// TraceID returns the trace ID ctx carries.
func TraceID(ctx context.Context) (string, bool) {
	t, ok := fromContext(ctx)
	return t.traceID, ok && t.traceID != ""
}

// Session returns the session ID ctx carries.
func Session(ctx context.Context) (string, bool) {
	t, ok := fromContext(ctx)
	return t.session, ok && t.session != ""
}

// Epoch returns the epoch ctx carries.
func Epoch(ctx context.Context) (uint64, bool) {
	t, ok := fromContext(ctx)
	return t.epoch, ok && t.hasEpoch
}
