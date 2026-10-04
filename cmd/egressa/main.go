//go:build linux

// Command egressa is the VPN client as users run it:
//
//	sudo egressa join <invite>   once, with the invite an admin gave you
//	egressa connect -sg           connect, leaving the Internet from gateway sg
//	egressa status                where the connection goes now
//	egressa disconnect            disconnect
//	egressa list                  the gateways you can leave from
//
// connect starts the client in the background (a systemd service, or a
// detached process on hosts without systemd) and returns once it is
// connected. Asked for another gateway while connected, it moves the
// same session there. Admins make invites with `egressa invite`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/client"
	"github.com/ngthdong/egressa/internal/cliutil"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/telemetry"
)

const usage = `egressa: VPN client

  sudo egressa join <invite>     join the VPN (once), with the invite from your admin
  egressa connect [-<gateway>]   connect; -<gateway> picks where you leave to the Internet (e.g. -sg)
  egressa status                 show the connection
  egressa disconnect             disconnect
  egressa list                   list the gateways
  egressa invite --controller URL [--token-file F]   (admins) make an invite
  egressa version

connect, disconnect, join and list ask for sudo when needed.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "join":
		err = cmdJoin(args)
	case "connect", "up":
		err = cmdConnect(args)
	case "disconnect", "down":
		err = cmdDisconnect()
	case "status":
		err = cmdStatus(os.Stdout)
	case "list", "gateways":
		err = cmdList(os.Stdout)
	case "invite":
		err = cmdInvite(args)
	case "run":
		err = cmdRun(args)
	case "version", "--version", "-version":
		fmt.Println(buildinfo.String("egressa"))
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "egressa: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "egressa:", err)
		os.Exit(1)
	}
}

// ensureRoot re-runs the command under sudo unless it is root already,
// keeping the EGRESSA_* settings.
func ensureRoot() error {
	if os.Geteuid() == 0 {
		return nil
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New("this needs root; run it with sudo")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var keep []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "EGRESSA_") {
			keep = append(keep, k)
		}
	}
	argv := []string{"sudo"}
	if len(keep) > 0 {
		argv = append(argv, "--preserve-env="+strings.Join(keep, ","))
	}
	argv = append(append(argv, "--", exe), os.Args[1:]...)
	return syscall.Exec(sudo, argv, os.Environ())
}

// parseGateway reads connect's argument: "-sg", "--sg" and "sg" all name
// gateway sg; no argument keeps the egress the client has.
func parseGateway(args []string) (string, error) {
	switch len(args) {
	case 0:
		return "", nil
	case 1:
		id := strings.TrimLeft(args[0], "-")
		if id == "" {
			return "", fmt.Errorf("bad gateway %q", args[0])
		}
		return id, nil
	}
	return "", fmt.Errorf("connect takes one gateway, got %q", strings.Join(args, " "))
}

func controllerClient(c conf) (*api.Client, error) { return api.NewClient(c.Controller, c.Token) }

func ctx10s() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func cmdJoin(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sudo egressa join <invite>")
	}
	if err := ensureRoot(); err != nil {
		return err
	}
	inv, err := decodeInvite(args[0])
	if err != nil {
		return err
	}
	ctl, err := api.NewClient(inv.Controller, inv.Token)
	if err != nil {
		return err
	}
	ctx, cancel := ctx10s()
	defer cancel()
	gws, err := ctl.Gateways(ctx)
	var se *api.StatusError
	if errors.As(err, &se) && se.Code == 401 {
		return errors.New("the controller rejected this invite's token; ask your admin for a new invite")
	}
	if err != nil {
		return fmt.Errorf("cannot reach the controller at %s: %w", inv.Controller, err)
	}
	c, _ := readConf(confPath())
	c.Controller, c.Token = inv.Controller, inv.Token
	if err := writeConf(confPath(), c); err != nil {
		return err
	}
	fmt.Printf("Joined %s.\n\n", inv.Controller)
	printGateways(os.Stdout, gws)
	if eg := egressIDs(gws); len(eg) > 0 {
		fmt.Printf("\nConnect with:  egressa connect -%s\n", eg[0])
	}
	return nil
}

func egressIDs(gws []api.Gateway) []string {
	var ids []string
	for _, g := range gws {
		if g.Roles.Has(control.RoleEgress) {
			ids = append(ids, g.ID)
		}
	}
	return ids
}

func printGateways(w io.Writer, gws []api.Gateway) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	pf(tw, "GATEWAY\tLEAVE FROM HERE\tSTATUS\tIP\n")
	for _, g := range gws {
		exit := "no"
		if g.Roles.Has(control.RoleEgress) {
			exit = "yes  (egressa connect -" + g.ID + ")"
		}
		state := "up"
		if !g.Alive {
			state = "DOWN"
		}
		host, _ := g.Host()
		pf(tw, "%s\t%s\t%s\t%s\n", g.ID, exit, state, host)
	}
	_ = tw.Flush()
}

func cmdList(w io.Writer) error {
	if err := ensureRoot(); err != nil {
		return err
	}
	c, err := readConf(confPath())
	if err != nil {
		return err
	}
	ctl, err := controllerClient(c)
	if err != nil {
		return err
	}
	ctx, cancel := ctx10s()
	defer cancel()
	gws, err := ctl.Gateways(ctx)
	if err != nil {
		return err
	}
	printGateways(w, gws)
	return nil
}

func cmdInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	controller := fs.String("controller", "", "the controller's URL, as clients reach it (https://...)")
	tokenFile := fs.String("token-file", "", "file holding the client token (default: $EGRESSA_CLIENT_TOKEN, else /etc/egressa/client.token)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *controller == "" {
		return errors.New("usage: egressa invite --controller https://ctl.example.com [--token-file F]")
	}
	file := *tokenFile
	if file == "" && os.Getenv("EGRESSA_CLIENT_TOKEN") == "" {
		file = "/etc/egressa/client.token"
	}
	token, err := cliutil.Secret(file, "EGRESSA_CLIENT_TOKEN")
	if err != nil {
		return err
	}
	inv, err := encodeInvite(*controller, token)
	if err != nil {
		return err
	}
	fmt.Println(inv)
	fmt.Fprintln(os.Stderr, "\nGive this to the user: they run  sudo egressa join <invite>.\nIt holds the client token: send it privately.")
	return nil
}

// pf writes to a terminal; a failed write there has nowhere to be
// reported.
func pf(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

const (
	liveFor     = 3 * time.Second
	connectWait = 40 * time.Second
)

// waitStatus waits until the running client's status satisfies ok.
func waitStatus(timeout time.Duration, ok func(client.Status) bool) (client.Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := client.ReadStatus(statusPath())
		if err == nil && st.Live(time.Now(), liveFor) && ok(st) {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, errors.New("timed out")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func running() (client.Status, bool) {
	st, err := client.ReadStatus(statusPath())
	return st, err == nil && st.Live(time.Now(), liveFor)
}

func cmdConnect(args []string) error {
	want, err := parseGateway(args)
	if err != nil {
		return err
	}
	if err := ensureRoot(); err != nil {
		return err
	}
	c, err := readConf(confPath())
	if err != nil {
		return err
	}
	ctl, err := controllerClient(c)
	if err != nil {
		return err
	}
	ctx, cancel := ctx10s()
	defer cancel()
	gws, err := ctl.Gateways(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach the controller: %w", err)
	}
	if want != "" {
		if err := checkEgress(gws, want); err != nil {
			return err
		}
		// New sessions start there; a running one is moved below.
		c.Egress = want
		if err := writeConf(confPath(), c); err != nil {
			return err
		}
	}

	st, up := running()
	if !up {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		svc := pickService()
		fmt.Println("Connecting...")
		if err := svc.Start(exe); err != nil {
			return err
		}
		if st, err = waitStatus(connectWait, func(s client.Status) bool { return s.SessionID != "" }); err != nil {
			return fmt.Errorf("the client did not come up within %s; %s", connectWait, svc.Hint())
		}
	}
	if want != "" && st.Egress != want {
		fmt.Printf("Moving the connection to leave from %s (open connections will break once)...\n", want)
		if err := switchEgress(ctl, gws, want); err != nil {
			return err
		}
		if st, err = waitStatus(20*time.Second, func(s client.Status) bool { return s.Egress == want }); err != nil {
			return fmt.Errorf("the controller moved the session, but the client has not followed yet; run: egressa status")
		}
	}
	printStatus(os.Stdout, st)
	return nil
}

func checkEgress(gws []api.Gateway, id string) error {
	g, ok := api.FindGateway(gws, id)
	switch {
	case !ok:
		return fmt.Errorf("no gateway %q; the gateways are: %s", id, strings.Join(egressIDs(gws), ", "))
	case !g.Roles.Has(control.RoleEgress):
		return fmt.Errorf("gateway %s does not lead to the Internet; pick one of: %s", id, strings.Join(egressIDs(gws), ", "))
	case !g.Alive:
		return fmt.Errorf("gateway %s is down right now", id)
	}
	return nil
}

// chooseAccess picks the entry for a session moving to egress: the egress
// itself when clients can connect to it, else the entry it has now. The
// client goes on optimizing its entry from there.
func chooseAccess(gws []api.Gateway, egress, current string) string {
	if g, ok := api.FindGateway(gws, egress); ok && g.Roles.Has(control.RoleAccess) {
		return egress
	}
	return current
}

// switchEgress moves the client's session to egress through the
// controller; the running client follows the move on its next poll.
func switchEgress(ctl *api.Client, gws []api.Gateway, egress string) error {
	st, _, err := client.LoadState(statePath())
	if err != nil {
		return err
	}
	if st.SessionID == "" {
		return errors.New("the client has no session yet")
	}
	ctx, cancel := ctx10s()
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		cs, err := ctl.ClientState(ctx, st.SessionID, st.Secret, 0, 0)
		if err != nil {
			return err
		}
		if cs.Session.Egress == egress {
			return nil
		}
		_, err = ctl.Migrate(ctx, st.SessionID, st.Secret, api.MigrateRequest{
			Epoch: cs.Session.Epoch, Access: chooseAccess(gws, egress, cs.Session.Access), Egress: egress,
		})
		if !errors.Is(err, api.ErrConflict) {
			return err
		}
		// The client moved its entry at the same moment; try again.
	}
	return errors.New("the session kept moving; try again")
}

func cmdDisconnect() error {
	if err := ensureRoot(); err != nil {
		return err
	}
	if _, up := running(); !up {
		fmt.Println("Not connected.")
		return nil
	}
	if err := pickService().Stop(); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, up := running(); !up {
			fmt.Println("Disconnected.")
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("the client is still running")
}

func cmdStatus(w io.Writer) error {
	st, up := running()
	if !up {
		pf(w, "Not connected.\n")
		return nil
	}
	printStatus(w, st)
	return nil
}

func printStatus(w io.Writer, st client.Status) {
	state := "Connected"
	if st.CurrentDead {
		state = "Connected, but the current path is not answering; switching"
	}
	if !st.ControllerUp {
		state += " (controller unreachable: no path changes until it is back)"
	}
	pf(w, "%s since %s.\n", state, st.Started.Local().Format("15:04:05"))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	exit := st.Egress
	if st.EgressIP != "" {
		// The gateway's endpoint: usually, not always, the address the
		// Internet sees (a gateway can leave through another interface).
		exit += "  (gateway " + st.EgressIP + ")"
	}
	pf(tw, "  Leaving from:\t%s\n", exit)
	pf(tw, "  Entering at:\t%s\n", st.Access)
	pf(tw, "  Virtual IP:\t%s\n", st.VirtualIP)
	pf(tw, "  Path changes:\t%d\n", st.Epoch-1)
	_ = tw.Flush()
	paths := slices.Clone(st.Paths)
	paths = slices.DeleteFunc(paths, func(p client.StatusPath) bool { return p.Egress != st.Egress })
	if len(paths) == 0 {
		return
	}
	pf(w, "  Paths to %s:\n", st.Egress)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range paths {
		mark := " "
		if p.Active {
			mark = "*"
		}
		cost := "not measured"
		if p.Usable {
			cost = fmt.Sprintf("%.1f ms", p.CostMS)
		}
		if !p.Reachable {
			cost += " (unreachable)"
		}
		via := "direct"
		if p.Access != p.Egress {
			via = "via " + p.Access
		}
		pf(tw, "   %s %s\t%s\n", mark, via, cost)
	}
	_ = tw.Flush()
}

func cmdRun(args []string) error {
	var logs cliutil.LogFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	logs.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensureRoot(); err != nil {
		return err
	}
	logger, err := logs.Logger("client", "")
	if err != nil {
		return err
	}
	c, err := readConf(confPath())
	if err != nil {
		return err
	}
	ctl, err := controllerClient(c)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reg, err := cliutil.Metrics(ctx, c.MetricsListen, "client", logger)
	if err != nil {
		return err
	}
	agent, err := client.New(client.Config{
		Controller: ctl, StateFile: statePath(), StatusFile: statusPath(),
		Interface: "egressa0", Egress: c.Egress, FullTunnel: true,
		Logger: logger, Metrics: telemetry.NewClientMetrics(reg), Tracer: telemetry.NewTracer(logger, nil),
	})
	if err != nil {
		return err
	}
	logger.Info("starting", "build", buildinfo.String("egressa"), "controller", c.Controller, "token", telemetry.Secret(c.Token))
	return agent.Run(ctx)
}
