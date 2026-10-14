package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// SpanRecord is one span read back from a JSON log.
type SpanRecord struct {
	TraceID    string
	Session    string
	Epoch      uint64
	Span       string
	Status     string
	Err        string
	Start      time.Time
	DurationMS float64
	// Role and Node say which process logged it.
	Role string
	Node string
	// Attrs are the span's own attributes (access, egress, cause, ...).
	Attrs map[string]string
}

// Process names the process that logged r: "gateway sg", "client".
func (r SpanRecord) Process() string {
	if r.Node != "" {
		return r.Role + " " + r.Node
	}
	return r.Role
}

var spanFields = []string{"time", "level", "msg", "trace_id", "session", "epoch", "span", "status", "err",
	"start", "duration_ms", "role", "node", "version"}

// ReadSpans reads the span records of a JSON log. A line may carry a
// prefix before its JSON object (journalctl's, say); lines that are not
// spans are skipped.
func ReadSpans(r io.Reader) ([]SpanRecord, error) {
	var out []SpanRecord
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '{')
		if i < 0 {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line[i:]), &m) != nil || m["msg"] != "span" {
			continue
		}
		rec := SpanRecord{
			TraceID: str(m["trace_id"]), Session: str(m["session"]), Span: str(m["span"]),
			Status: str(m["status"]), Err: str(m["err"]), Role: str(m["role"]), Node: str(m["node"]),
			Attrs: map[string]string{},
		}
		if e, ok := m["epoch"].(float64); ok {
			rec.Epoch = uint64(e)
		}
		rec.DurationMS, _ = m["duration_ms"].(float64)
		rec.Start, _ = time.Parse(time.RFC3339Nano, str(m["start"]))
		for k, v := range m {
			if !slices.Contains(spanFields, k) {
				rec.Attrs[k] = str(v)
			}
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return fmt.Sprintf("%g", x)
	default:
		return fmt.Sprint(x)
	}
}

// Migration is the spans of one migration, from every process, in the
// order they started.
type Migration struct {
	TraceID string
	Session string
	Epoch   uint64
	Spans   []SpanRecord
}

// Start is when the first span started; End when the last one ended.
func (m Migration) Start() time.Time { return m.Spans[0].Start }

// End is when the last span ended.
func (m Migration) End() time.Time {
	var end time.Time
	for _, s := range m.Spans {
		if e := s.Start.Add(time.Duration(s.DurationMS * float64(time.Millisecond))); e.After(end) {
			end = e
		}
	}
	return end
}

// Status is "ok", or the first span that did not end ok.
func (m Migration) Status() string {
	for _, s := range m.Spans {
		if s.Status != string(StatusOK) {
			return s.Span + " " + s.Status
		}
	}
	return string(StatusOK)
}

// Migrations groups spans by trace into migrations, oldest first. Spans
// that are not migration.* are left out.
func Migrations(spans []SpanRecord) []Migration {
	byTrace := map[string]*Migration{}
	var order []string
	for _, s := range spans {
		if !strings.HasPrefix(s.Span, "migration.") || s.TraceID == "" {
			continue
		}
		m := byTrace[s.TraceID]
		if m == nil {
			m = &Migration{TraceID: s.TraceID, Session: s.Session, Epoch: s.Epoch}
			byTrace[s.TraceID] = m
			order = append(order, s.TraceID)
		}
		m.Spans = append(m.Spans, s)
	}
	out := make([]Migration, 0, len(order))
	for _, id := range order {
		m := byTrace[id]
		slices.SortStableFunc(m.Spans, func(a, b SpanRecord) int { return a.Start.Compare(b.Start) })
		out = append(out, *m)
	}
	slices.SortStableFunc(out, func(a, b Migration) int { return a.Start().Compare(b.Start()) })
	return out
}

// WriteTimeline prints each migration: a header (trace, session, epoch,
// result, total time), then one line per span with its offset from the
// first span's start.
func WriteTimeline(w io.Writer, ms []Migration) error {
	if len(ms) == 0 {
		_, err := fmt.Fprintln(w, "no migration spans found (were the processes run with --log-format json?)")
		return err
	}
	for i, m := range ms {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		total := m.End().Sub(m.Start())
		if _, err := fmt.Fprintf(w, "migration to epoch %d  session %s  trace %s  %s  %s\n",
			m.Epoch, m.Session, m.TraceID, m.Status(), fmtMS(total)); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, s := range m.Spans {
			line := fmt.Sprintf("  +%s\t%s\t%s\t%s\t%s\t%s",
				fmtMS(s.Start.Sub(m.Start())), s.Process(), s.Span, s.Status, fmtMS(time.Duration(s.DurationMS*float64(time.Millisecond))), attrs(s))
			if _, err := fmt.Fprintln(tw, line); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func fmtMS(d time.Duration) string {
	return fmt.Sprintf("%.3f ms", float64(d)/float64(time.Millisecond))
}

func attrs(s SpanRecord) string {
	keys := make([]string, 0, len(s.Attrs))
	for k := range s.Attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		parts = append(parts, k+"="+s.Attrs[k])
	}
	if s.Err != "" {
		parts = append(parts, "err="+s.Err)
	}
	return strings.Join(parts, " ")
}
