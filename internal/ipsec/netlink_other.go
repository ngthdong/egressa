//go:build !linux

package ipsec

import (
	"errors"
	"net/netip"
)

var errNetlinkUnsupported = errors.New("ipsec: netlink is only available on Linux")

// NetlinkNet is unavailable outside Linux; every method fails.
type NetlinkNet struct{}

var _ Net = (*NetlinkNet)(nil)

// NewNetlinkNet always fails outside Linux.
func NewNetlinkNet() (*NetlinkNet, error) { return nil, errNetlinkUnsupported }

func (n *NetlinkNet) Close() {}

func (n *NetlinkNet) AddXfrmInterface(string, uint32, string) error { return errNetlinkUnsupported }
func (n *NetlinkNet) DeleteLink(string) error                       { return errNetlinkUnsupported }
func (n *NetlinkNet) AddAddr(string, netip.Prefix) error            { return errNetlinkUnsupported }
func (n *NetlinkNet) SetLinkUp(string) error                        { return errNetlinkUnsupported }
func (n *NetlinkNet) RouteAdd(Route) error                          { return errNetlinkUnsupported }
func (n *NetlinkNet) RouteReplace(Route) error                      { return errNetlinkUnsupported }
func (n *NetlinkNet) RouteDel(Route) error                          { return errNetlinkUnsupported }
func (n *NetlinkNet) RouteGet(netip.Addr) (Route, error)            { return Route{}, errNetlinkUnsupported }
func (n *NetlinkNet) DefaultRoute(Family) (Route, error)            { return Route{}, errNetlinkUnsupported }
func (n *NetlinkNet) RuleAdd(Rule) error                            { return errNetlinkUnsupported }
func (n *NetlinkNet) RuleDel(Rule) error                            { return errNetlinkUnsupported }
func (n *NetlinkNet) XfrmStates() ([]XfrmState, error)              { return nil, errNetlinkUnsupported }
