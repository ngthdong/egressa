// Command vpnctl is the operator's tool for egressa testbeds.
//
//	vpnctl trace [--session ID] <log>...       timeline of every migration in JSON logs
//	vpnctl netem apply --dev D --rule IP:SHAPE...  shape traffic from this host
//	vpnctl netem clear --dev D                 remove the shaping
//	vpnctl netem show --dev D                  print it
//	vpnctl netem run --scenario F --node N --hosts n=ip,... --dev D [--start UNIX]
//	                                           run a scenario's steps for one node
//
// A SHAPE is delay=80ms,jitter=5ms,loss=1,rate=10mbit (any subset).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/netem"
	"github.com/ngthdong/egressa/internal/telemetry"
)

const usage = `vpnctl: egressa testbed tool

  vpnctl trace [--session ID] <log>...      timeline of each migration, from JSON logs ("-" is stdin)
  vpnctl netem apply --dev D --rule IP:SHAPE [--rule ...]
                                            shape traffic leaving D, per destination
  vpnctl netem clear --dev D                remove all shaping from D
  vpnctl netem show --dev D                 print D's qdiscs and filters
  vpnctl netem run --scenario F --node N --hosts n=ip,... --dev D [--start UNIX]
                                            run scenario F's steps for node N
  vpnctl version

SHAPE is delay=80ms,jitter=5ms,loss=1,rate=10mbit (any subset; loss in %).
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "vpnctl:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("see vpnctl help")

func run(args []string, stdout io.Writer, stdin io.Reader) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errUsage
	}
	switch args[0] {
	case "trace":
		return cmdTrace(args[1:], stdout, stdin)
	case "netem":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return cmdNetem(ctx, args[1:], stdout, netem.Exec)
	case "version", "--version":
		_, err := fmt.Fprintln(stdout, buildinfo.String("vpnctl"))
		return err
	case "help", "-h", "--help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	}
	return fmt.Errorf("unknown command %q; %w", args[0], errUsage)
}

func cmdTrace(args []string, stdout io.Writer, stdin io.Reader) error {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	session := fs.String("session", "", "only this session's migrations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: vpnctl trace [--session ID] <log>... (JSON logs of the client, controller and gateways)")
	}
	var spans []telemetry.SpanRecord
	for _, path := range fs.Args() {
		r := stdin
		if path != "-" {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			r = f
		}
		s, err := telemetry.ReadSpans(r)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		spans = append(spans, s...)
	}
	ms := telemetry.Migrations(spans)
	if *session != "" {
		kept := ms[:0]
		for _, m := range ms {
			if m.Session == *session {
				kept = append(kept, m)
			}
		}
		ms = kept
	}
	return telemetry.WriteTimeline(stdout, ms)
}

// rules collects repeated --rule IP:SHAPE flags.
type rules map[netip.Addr]netem.Shape

func (r rules) String() string { return fmt.Sprint(map[netip.Addr]netem.Shape(r)) }

func (r rules) Set(v string) error {
	ip, spec, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("rule %q must be IP:SHAPE", v)
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	s, err := netem.ParseShape(spec)
	if err != nil {
		return err
	}
	r[a] = s
	return nil
}

func cmdNetem(ctx context.Context, args []string, stdout io.Writer, runner netem.Runner) error {
	if len(args) == 0 {
		return errors.New("usage: vpnctl netem apply|clear|show|run ...")
	}
	fs := flag.NewFlagSet("netem "+args[0], flag.ContinueOnError)
	dev := fs.String("dev", "", "the network interface traffic leaves through")
	rs := rules{}
	scenario := fs.String("scenario", "", "(run) scenario file")
	node := fs.String("node", "", "(run) which node this host is in the scenario")
	hosts := fs.String("hosts", "", "(run) the scenario's nodes' addresses: client=10.0.0.2,gw1=...")
	startAt := fs.Int64("start", 0, "(run) unix time to count the steps from; default now")
	if args[0] == "apply" {
		fs.Var(rs, "rule", "IP:SHAPE, e.g. 192.0.2.11:delay=80ms,loss=1 (repeatable)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dev == "" {
		return errors.New("--dev is required")
	}
	d := netem.Device{Name: *dev, Run: runner}
	switch args[0] {
	case "apply":
		if len(rs) == 0 {
			return errors.New("give at least one --rule IP:SHAPE (or use clear)")
		}
		return d.Apply(rs)
	case "clear":
		return d.Clear()
	case "show":
		out, err := d.Show()
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(stdout, out)
		return err
	case "run":
		if *scenario == "" || *node == "" || *hosts == "" {
			return errors.New("run needs --scenario, --node and --hosts")
		}
		s, err := netem.Load(*scenario)
		if err != nil {
			return err
		}
		h, err := netem.ParseHosts(*hosts)
		if err != nil {
			return err
		}
		start := time.Now()
		if *startAt > 0 {
			start = time.Unix(*startAt, 0)
		}
		logf := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
		logf("scenario %s on %s (%s), starting %s, %s long", s.Name, *node, *dev,
			start.Format(time.RFC3339), s.Duration())
		// Note whether a step shaped the device, so that an interrupt or a
		// failure halfway removes that shaping, and only that.
		shaped := false
		d.Run = func(name string, args ...string) ([]byte, error) {
			if name == "tc" && len(args) > 1 && args[0] == "qdisc" && args[1] == "add" {
				shaped = true
			}
			return runner(name, args...)
		}
		err = netem.Run(ctx, s, *node, h, d, start, netem.RealClock, logf)
		if err != nil && shaped {
			if cerr := d.Clear(); cerr != nil {
				return errors.Join(err, fmt.Errorf("could not remove the shaping from %s: %w", *dev, cerr))
			}
			logf("stopped: removed the shaping from %s", *dev)
		}
		return err
	}
	return fmt.Errorf("unknown netem command %q", args[0])
}
