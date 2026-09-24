package tunnel

import (
	"testing"
	"time"
)

func TestHandshake(t *testing.T) {
	client, gateway, _, _, clientKP, gatewayKP := testPeerPair(t, time.Second)

	// wireguard-go primes a freshly-added peer to send its handshake-init
	// immediately. That first attempt can be lost (e.g. it can beat the
	// other side's AddPeer, which is still configuring the responder), and
	// the library then waits device.RekeyTimeout (5s, plus jitter) before
	// retrying. A single retry cycle is the common case locally (~5.1s),
	// but a busier CI runner can occasionally lose the retry too, pushing
	// completion out to a second cycle (~10.7s with jitter) -- a 10s
	// budget sits right on that boundary and flakes under exactly that
	// load. Give it real headroom instead of chasing the exact number.
	const handshakeTimeout = 25 * time.Second
	waitForHandshake(t, client, gatewayKP.Public, handshakeTimeout)
	waitForHandshake(t, gateway, clientKP.Public, handshakeTimeout)
}
