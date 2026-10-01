package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/strongswan/govici/vici"
)

// vici wire protocol constants (strongSwan's src/libcharon/plugins/vici/
// README.md). govici keeps its own copies unexported.
const (
	pktCmdRequest      = 0
	pktCmdResponse     = 1
	pktCmdUnknown      = 2
	pktEventRegister   = 3
	pktEventUnregister = 4
	pktEventConfirm    = 5
	pktEventUnknown    = 6
	pktEvent           = 7

	elSectionStart = 1
	elSectionEnd   = 2
	elKeyValue     = 3
	elListStart    = 4
	elListItem     = 5
	elListEnd      = 6
)

// streamEvents maps a streaming command to the event charon streams it
// with.
var streamEvents = map[string]string{
	"list-sas": "list-sa",
	"initiate": "control-log",
}

// viciHandler answers one command: the streamed event messages (sent only
// if the client registered for the command's stream event) and then the
// response. A nil response makes the fake drop the connection instead.
type viciHandler func(req *vici.Message) (stream []*vici.Message, resp *vici.Message)

type viciRequest struct {
	cmd string
	msg *vici.Message
}

// fakeCharon speaks the vici wire protocol over in-memory pipes, so the
// real govici client code runs against it unmodified.
type fakeCharon struct {
	t *testing.T

	mu       sync.Mutex
	handlers map[string]viciHandler
	conns    map[*fakeViciConn]struct{}
	requests []viciRequest
	dials    int
	dialErr  error
	// knownEvents lists the event names registration succeeds for.
	knownEvents map[string]bool
}

type fakeViciConn struct {
	conn   net.Conn
	wmu    sync.Mutex
	mu     sync.Mutex
	events map[string]bool
}

func newFakeCharon(t *testing.T) *fakeCharon {
	f := &fakeCharon{
		t:        t,
		handlers: map[string]viciHandler{},
		conns:    map[*fakeViciConn]struct{}{},
		knownEvents: map[string]bool{
			"ike-updown": true, "child-updown": true, "list-sa": true, "control-log": true,
		},
	}
	t.Cleanup(f.closeAll)
	return f
}

// setDialErr makes every later dial fail with err (nil restores it).
func (f *fakeCharon) setDialErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialErr = err
}

// refuseEvents makes every later event registration fail.
func (f *fakeCharon) refuseEvents() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.knownEvents = map[string]bool{}
}

func (f *fakeCharon) handle(cmd string, h viciHandler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[cmd] = h
}

// ok answers a command with success=yes.
func ok(*vici.Message) ([]*vici.Message, *vici.Message) {
	return nil, newMsg("success", "yes")
}

// fail answers a command with success=no and errmsg.
func fail(errmsg string) viciHandler {
	return func(*vici.Message) ([]*vici.Message, *vici.Message) {
		return nil, newMsg("success", "no", "errmsg", errmsg)
	}
}

func (f *fakeCharon) dial(context.Context, string, string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dials++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	client, server := net.Pipe()
	c := &fakeViciConn{conn: server, events: map[string]bool{}}
	f.conns[c] = struct{}{}
	go f.serve(c)
	return client, nil
}

func (f *fakeCharon) newIKE(t *testing.T, opts ...ViciOption) *ViciIKE {
	t.Helper()
	v, err := NewViciIKE(context.Background(), append([]ViciOption{WithViciDialer(f.dial)}, opts...)...)
	if err != nil {
		t.Fatalf("NewViciIKE: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func (f *fakeCharon) lastRequest(cmd string) *vici.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].cmd == cmd {
			return f.requests[i].msg
		}
	}
	return nil
}

func (f *fakeCharon) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

// emit sends a named event to every connection registered for it, and
// reports how many received it.
func (f *fakeCharon) emit(name string, m *vici.Message) int {
	f.mu.Lock()
	conns := make([]*fakeViciConn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	n := 0
	for _, c := range conns {
		c.mu.Lock()
		registered := c.events[name]
		c.mu.Unlock()
		if registered && c.write(pktEvent, name, m) == nil {
			n++
		}
	}
	return n
}

// subscribers counts connections registered for event name.
func (f *fakeCharon) subscribers(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for c := range f.conns {
		c.mu.Lock()
		if c.events[name] {
			n++
		}
		c.mu.Unlock()
	}
	return n
}

// closeAll drops every connection, as a charon restart would.
func (f *fakeCharon) closeAll() {
	f.mu.Lock()
	conns := f.conns
	f.conns = map[*fakeViciConn]struct{}{}
	f.mu.Unlock()
	for c := range conns {
		_ = c.conn.Close()
	}
}

func (f *fakeCharon) serve(c *fakeViciConn) {
	defer func() {
		_ = c.conn.Close()
		f.mu.Lock()
		delete(f.conns, c)
		f.mu.Unlock()
	}()
	for {
		ptype, name, msg, err := readPacket(c.conn)
		if err != nil {
			return
		}
		switch ptype {
		case pktEventRegister, pktEventUnregister:
			f.mu.Lock()
			known := f.knownEvents[name]
			f.mu.Unlock()
			if !known {
				_ = c.write(pktEventUnknown, "", nil)
				continue
			}
			c.mu.Lock()
			c.events[name] = ptype == pktEventRegister
			c.mu.Unlock()
			_ = c.write(pktEventConfirm, "", nil)
		case pktCmdRequest:
			f.mu.Lock()
			f.requests = append(f.requests, viciRequest{cmd: name, msg: msg})
			h := f.handlers[name]
			f.mu.Unlock()
			if h == nil {
				_ = c.write(pktCmdUnknown, "", nil)
				continue
			}
			stream, resp := h(msg)
			if ev, ok := streamEvents[name]; ok {
				c.mu.Lock()
				registered := c.events[ev]
				c.mu.Unlock()
				if registered {
					for _, s := range stream {
						_ = c.write(pktEvent, ev, s)
					}
				}
			}
			if resp == nil {
				return // simulate the daemon dying mid-command
			}
			_ = c.write(pktCmdResponse, "", resp)
		default:
			f.t.Errorf("fake charon: unexpected packet type %d", ptype)
			return
		}
	}
}

func (c *fakeViciConn) write(ptype byte, name string, m *vici.Message) error {
	var body bytes.Buffer
	body.WriteByte(ptype)
	if ptype == pktEvent {
		body.WriteByte(byte(len(name)))
		body.WriteString(name)
	}
	if m != nil {
		encodeViciMessage(&body, m)
	}
	var pkt bytes.Buffer
	_ = binary.Write(&pkt, binary.BigEndian, uint32(body.Len()))
	pkt.Write(body.Bytes())
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(pkt.Bytes())
	return err
}

func readPacket(r io.Reader) (ptype byte, name string, msg *vici.Message, err error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return 0, "", nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, "", nil, err
	}
	ptype = buf[0]
	rest := buf[1:]
	switch ptype {
	case pktCmdRequest, pktEventRegister, pktEventUnregister, pktEvent:
		l := int(rest[0])
		name = string(rest[1 : 1+l])
		rest = rest[1+l:]
	}
	msg, err = decodeViciMessage(rest)
	return ptype, name, msg, err
}

func encodeViciMessage(b *bytes.Buffer, m *vici.Message) {
	for _, k := range m.Keys() {
		switch v := m.Get(k).(type) {
		case string:
			b.WriteByte(elKeyValue)
			b.WriteByte(byte(len(k)))
			b.WriteString(k)
			_ = binary.Write(b, binary.BigEndian, uint16(len(v)))
			b.WriteString(v)
		case []string:
			b.WriteByte(elListStart)
			b.WriteByte(byte(len(k)))
			b.WriteString(k)
			for _, item := range v {
				b.WriteByte(elListItem)
				_ = binary.Write(b, binary.BigEndian, uint16(len(item)))
				b.WriteString(item)
			}
			b.WriteByte(elListEnd)
		case *vici.Message:
			b.WriteByte(elSectionStart)
			b.WriteByte(byte(len(k)))
			b.WriteString(k)
			encodeViciMessage(b, v)
			b.WriteByte(elSectionEnd)
		}
	}
}

func decodeViciMessage(data []byte) (*vici.Message, error) {
	root := vici.NewMessage()
	stack := []*vici.Message{root}
	names := []string{""}
	var listKey string
	var items []string
	inList := false
	r := bytes.NewReader(data)
	readName := func() (string, error) {
		l, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		s := make([]byte, l)
		_, err = io.ReadFull(r, s)
		return string(s), err
	}
	readValue := func() (string, error) {
		var l uint16
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return "", err
		}
		s := make([]byte, l)
		_, err := io.ReadFull(r, s)
		return string(s), err
	}
	for r.Len() > 0 {
		el, _ := r.ReadByte()
		switch el {
		case elSectionStart:
			n, err := readName()
			if err != nil {
				return nil, err
			}
			stack = append(stack, vici.NewMessage())
			names = append(names, n)
		case elSectionEnd:
			if len(stack) < 2 {
				return nil, errors.New("unbalanced section end")
			}
			sec, n := stack[len(stack)-1], names[len(names)-1]
			stack, names = stack[:len(stack)-1], names[:len(names)-1]
			if err := stack[len(stack)-1].Set(n, sec); err != nil {
				return nil, err
			}
		case elKeyValue:
			k, err := readName()
			if err != nil {
				return nil, err
			}
			v, err := readValue()
			if err != nil {
				return nil, err
			}
			if err := stack[len(stack)-1].Set(k, v); err != nil {
				return nil, err
			}
		case elListStart:
			k, err := readName()
			if err != nil {
				return nil, err
			}
			listKey, items, inList = k, []string{}, true
		case elListItem:
			if !inList {
				return nil, errors.New("list item outside a list")
			}
			v, err := readValue()
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		case elListEnd:
			if err := stack[len(stack)-1].Set(listKey, items); err != nil {
				return nil, err
			}
			inList = false
		default:
			return nil, fmt.Errorf("unknown element type %d", el)
		}
	}
	return root, nil
}

// shortTempDir returns a fresh directory with a short path. A unix socket
// path is limited to about 108 bytes and is silently truncated beyond
// that, and t.TempDir embeds the (possibly long) test name.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "egv")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
