package ipsec

import "time"

// IKE_SA and CHILD_SA states as charon reports them.
const (
	IKEStateEstablished  = "ESTABLISHED"
	ChildStateInstalled  = "INSTALLED"
	ChildStateRekeyed    = "REKEYED"
	ChildStateInstalling = "INSTALLING"
)

// ChildSA is one CHILD_SA as charon reports it in list-sas.
type ChildSA struct {
	Name     string
	UniqueID uint64
	State    string
	Mode     string
	Protocol string
	// SPIIn and SPIOut are the SPIs as charon prints them: hex without a
	// 0x prefix.
	SPIIn   string
	SPIOut  string
	IfIDIn  uint32
	IfIDOut uint32
	EncrAlg string

	BytesIn, PacketsIn   uint64
	BytesOut, PacketsOut uint64
	// InstalledFor is how long ago the SA was installed.
	InstalledFor time.Duration

	LocalTS  []string
	RemoteTS []string
}

// IKESA is one IKE_SA as charon reports it in list-sas or an updown
// event.
type IKESA struct {
	Name       string
	UniqueID   uint64
	State      string
	LocalHost  string
	RemoteHost string
	LocalID    string
	RemoteID   string
	Initiator  bool
	EncrAlg    string
	PRFAlg     string
	DHGroup    string
	// EstablishedFor is how long ago the IKE_SA was established.
	EstablishedFor time.Duration
	Children       []ChildSA
}

// Warm reports whether s is a usable standby: the IKE_SA is established
// and at least one CHILD_SA is installed. No route needs to point at it.
func (s IKESA) Warm() bool {
	if s.State != IKEStateEstablished {
		return false
	}
	for _, c := range s.Children {
		if c.State == ChildStateInstalled {
			return true
		}
	}
	return false
}

// FindIKE returns the newest IKE_SA (highest unique id) named name.
func FindIKE(sas []IKESA, name string) (IKESA, bool) {
	var best IKESA
	found := false
	for _, s := range sas {
		if s.Name == name && (!found || s.UniqueID > best.UniqueID) {
			best, found = s, true
		}
	}
	return best, found
}
