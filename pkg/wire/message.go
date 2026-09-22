package wire

import (
	"encoding/json"
	"fmt"
)

type MessageType string

const (
	MsgHello                MessageType = "HELLO"
	MsgHeartbeat            MessageType = "HEARTBEAT"
	MsgMigratePrepare       MessageType = "MIGRATE_PREPARE"
	MsgSessionStateTransfer MessageType = "SESSION_STATE_TRANSFER"
	MsgSessionReady         MessageType = "SESSION_READY"
	MsgMigrateCommit        MessageType = "MIGRATE_COMMIT"
	MsgDrain                MessageType = "DRAIN"
	MsgMigrateComplete      MessageType = "MIGRATE_COMPLETE"
	MsgMigrateAbort         MessageType = "MIGRATE_ABORT"
)

// Envelope wraps every control-plane message. SessionID and Epoch are kept
// at the envelope level so receivers can route, log, and reject stale
// messages without decoding the payload.
type Envelope struct {
	Type      MessageType     `json:"type"`
	SessionID uint64          `json:"session_id"`
	Epoch     uint32          `json:"epoch"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

func (e Envelope) Encode() ([]byte, error) {
	return json.Marshal(e)
}

func DecodeEnvelope(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("wire: DecodeEnvelope: %w", err)
	}
	if e.Type == "" {
		return Envelope{}, fmt.Errorf("wire: DecodeEnvelope: missing required field %q", "type")
	}
	return e, nil
}

// MigratePreparePayload is the payload of a MIGRATE_PREPARE message: a
// request to arm a target gateway for a session at a new epoch.
type MigratePreparePayload struct {
	TargetGateway string `json:"target_gateway"`
	NewEpoch      uint32 `json:"new_epoch"`
}

// NewMigratePrepare builds a ready-to-send MIGRATE_PREPARE envelope.
func NewMigratePrepare(sessionID uint64, currentEpoch uint32, targetGateway string, newEpoch uint32) (Envelope, error) {
	payload, err := json.Marshal(MigratePreparePayload{
		TargetGateway: targetGateway,
		NewEpoch:      newEpoch,
	})
	if err != nil {
		return Envelope{}, fmt.Errorf("wire: NewMigratePrepare: %w", err)
	}
	return Envelope{
		Type:      MsgMigratePrepare,
		SessionID: sessionID,
		Epoch:     currentEpoch,
		Payload:   payload,
	}, nil
}

// AsMigratePrepare decodes e's payload as a MigratePreparePayload.
func (e Envelope) AsMigratePrepare() (MigratePreparePayload, error) {
	if e.Type != MsgMigratePrepare {
		return MigratePreparePayload{}, fmt.Errorf("wire: AsMigratePrepare: envelope has type %q, not %q", e.Type, MsgMigratePrepare)
	}
	var p MigratePreparePayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return MigratePreparePayload{}, fmt.Errorf("wire: AsMigratePrepare: %w", err)
	}
	return p, nil
}
