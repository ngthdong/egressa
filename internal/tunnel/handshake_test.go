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
	// retrying, so the wait budget here must clear one full retry cycle,
	// not just "long enough for a network round trip".
	const handshakeTimeout = 10 * time.Second
	waitForHandshake(t, client, gatewayKP.Public, handshakeTimeout)
	waitForHandshake(t, gateway, clientKP.Public, handshakeTimeout)
}
