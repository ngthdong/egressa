package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ngthdong/egressa/internal/api"
)

// Status is what a running client reports about itself in
// Config.StatusFile, rewritten after every decision pass, so other
// programs (the egressa CLI) can tell whether it is up and where its
// session is.
type Status struct {
	PID          int          `json:"pid"`
	Started      time.Time    `json:"started"`
	Updated      time.Time    `json:"updated"`
	SessionID    string       `json:"session_id"`
	VirtualIP    string       `json:"virtual_ip"`
	Access       string       `json:"access"`
	Egress       string       `json:"egress"`
	EgressIP     string       `json:"egress_ip,omitempty"`
	Epoch        uint64       `json:"epoch"`
	CurrentDead  bool         `json:"current_dead"`
	ControllerUp bool         `json:"controller_up"`
	Paths        []StatusPath `json:"paths"`
}

// StatusPath is one path the client scored.
type StatusPath struct {
	Access    string  `json:"access"`
	Egress    string  `json:"egress"`
	CostMS    float64 `json:"cost_ms,omitempty"`
	Usable    bool    `json:"usable"`
	Reachable bool    `json:"reachable"`
	Active    bool    `json:"active"`
}

// ReadStatus reads a status file.
func ReadStatus(path string) (Status, error) {
	var st Status
	data, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("client: parse status file %s: %w", path, err)
	}
	return st, nil
}

// Live reports whether the client that wrote st is still running and
// has updated it within maxAge.
func (st Status) Live(now time.Time, maxAge time.Duration) bool {
	if st.PID <= 0 || now.Sub(st.Updated) > maxAge {
		return false
	}
	err := syscall.Kill(st.PID, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func writeStatus(path string, st Status) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// statusOf builds the status of one decision pass.
func statusOf(sess api.Session, gws []api.Gateway, paths []Path, dead, ctlUp bool, dec Decision) Status {
	st := Status{
		PID: os.Getpid(), SessionID: sess.ID, VirtualIP: sess.VirtualIP.String(),
		Access: sess.Access, Egress: sess.Egress, Epoch: sess.Epoch,
		CurrentDead: dead, ControllerUp: ctlUp,
	}
	if g, ok := api.FindGateway(gws, sess.Egress); ok {
		if host, err := g.Host(); err == nil {
			st.EgressIP = host.String()
		}
	}
	for i, p := range paths {
		sp := StatusPath{Access: p.Access, Egress: p.Egress, Reachable: p.Reachable,
			Active: p.Access == sess.Access && p.Egress == sess.Egress}
		measured := true
		for _, seg := range p.Segments {
			measured = measured && seg.N > 0
		}
		if i < len(dec.Evals) && measured && !math.IsInf(dec.Evals[i].Cost, 0) {
			sp.CostMS, sp.Usable = dec.Evals[i].Cost/1000, true
		}
		st.Paths = append(st.Paths, sp)
	}
	return st
}
