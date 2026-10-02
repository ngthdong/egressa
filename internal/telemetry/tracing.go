package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strconv"
	"time"
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

// Status is how a span ended.
type Status string

// Span statuses.
const (
	StatusOK       Status = "ok"
	StatusError    Status = "error"
	StatusConflict Status = "conflict"
)

// Tracer writes spans as log records. A nil *Tracer is valid and records
// nothing.
type Tracer struct {
	logger *slog.Logger
	now    func() time.Time
}

// NewTracer returns a tracer logging to logger, reading time from now
// (time.Now if nil).
func NewTracer(logger *slog.Logger, now func() time.Time) *Tracer {
	if logger == nil {
		logger = Discard()
	}
	if now == nil {
		now = time.Now
	}
	return &Tracer{logger: logger, now: now}
}

// Now is the tracer's clock.
func (t *Tracer) Now() time.Time {
	if t == nil {
		return time.Now()
	}
	return t.now()
}

// Span is one timed phase of a trace. It is logged once, when it ends.
// A nil *Span is valid and does nothing.
type Span struct {
	t     *Tracer
	ctx   context.Context
	name  string
	start time.Time
	attrs []slog.Attr
	ended bool
}

// Start begins span name now, in the trace ctx carries.
func (t *Tracer) Start(ctx context.Context, name string, attrs ...slog.Attr) *Span {
	return t.StartAt(ctx, name, t.Now(), attrs...)
}

// StartAt begins span name at start: for a phase only known to have
// happened once it is over, such as a decision that turned out to move
// the session.
func (t *Tracer) StartAt(ctx context.Context, name string, start time.Time, attrs ...slog.Attr) *Span {
	if t == nil {
		return nil
	}
	return &Span{t: t, ctx: ctx, name: name, start: start, attrs: attrs}
}

// SetAttrs adds attributes to the span's record.
func (s *Span) SetAttrs(attrs ...slog.Attr) {
	if s == nil {
		return
	}
	s.attrs = append(s.attrs, attrs...)
}

// End ends the span: status ok if err is nil, error otherwise.
func (s *Span) End(err error) {
	st := StatusOK
	if err != nil {
		st = StatusError
	}
	s.EndStatus(st, err)
}

// EndStatus ends the span with status st and logs it: trace_id, session
// and epoch from its context, span, start, duration_ms, status, err if
// any, then its attributes. Only the first end is logged.
func (s *Span) EndStatus(st Status, err error) {
	if s == nil || s.ended {
		return
	}
	s.ended = true
	end := s.t.now()
	rec := make([]slog.Attr, 0, 8+len(s.attrs))
	if t, ok := fromContext(s.ctx); ok {
		if t.traceID != "" {
			rec = append(rec, slog.String("trace_id", t.traceID))
		}
		if t.session != "" {
			rec = append(rec, slog.String("session", t.session))
		}
		if t.hasEpoch {
			rec = append(rec, slog.Uint64("epoch", t.epoch))
		}
	}
	rec = append(rec,
		slog.String("span", s.name),
		slog.String("start", s.start.UTC().Format(time.RFC3339Nano)),
		slog.Float64("duration_ms", float64(end.Sub(s.start).Microseconds())/1000),
		slog.String("status", string(st)),
	)
	if err != nil {
		rec = append(rec, Err(err))
	}
	rec = append(rec, s.attrs...)
	level := slog.LevelInfo
	if st == StatusError {
		level = slog.LevelWarn
	}
	// The trace fields are in rec already; log without the context so a
	// ContextHandler does not add them twice.
	s.t.logger.LogAttrs(context.Background(), level, "span", rec...)
}
