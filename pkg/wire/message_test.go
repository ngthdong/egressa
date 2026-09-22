package wire

import (
	"strings"
	"testing"
)

func TestEnvelope_RoundTrip(t *testing.T) {
	original, err := NewMigratePrepare(
		/* sessionID */ 12345,
		/* currentEpoch */ 7,
		/* targetGateway */ "sg-access-1",
		/* newEpoch */ 8,
	)
	if err != nil {
		t.Fatalf("NewMigratePrepare: %v", err)
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}

	if decoded.Type != MsgMigratePrepare {
		t.Errorf("Type = %q, want %q", decoded.Type, MsgMigratePrepare)
	}
	if decoded.SessionID != 12345 {
		t.Errorf("SessionID = %d, want 12345", decoded.SessionID)
	}
	if decoded.Epoch != 7 {
		t.Errorf("Epoch = %d, want 7", decoded.Epoch)
	}

	payload, err := decoded.AsMigratePrepare()
	if err != nil {
		t.Fatalf("AsMigratePrepare: %v", err)
	}
	if payload.TargetGateway != "sg-access-1" {
		t.Errorf("TargetGateway = %q, want %q", payload.TargetGateway, "sg-access-1")
	}
	if payload.NewEpoch != 8 {
		t.Errorf("NewEpoch = %d, want 8", payload.NewEpoch)
	}
}

func TestEnvelope_WrongTypeAccessor(t *testing.T) {
	// A HEARTBEAT envelope has no MigratePreparePayload, AsMigratePrepare
	// must refuse to guess, not silently return a zero-value payload that
	// looks plausible.
	hb := Envelope{Type: MsgHeartbeat, SessionID: 1}
	if _, err := hb.AsMigratePrepare(); err == nil {
		t.Fatal("AsMigratePrepare on a HEARTBEAT envelope: expected error, got nil")
	}
}

func TestDecodeEnvelope_MissingType(t *testing.T) {
	if _, err := DecodeEnvelope([]byte(`{"session_id": 1}`)); err == nil {
		t.Fatal("DecodeEnvelope with missing type: expected error, got nil")
	}
}

func TestDecodeEnvelope_Malformed(t *testing.T) {
	if _, err := DecodeEnvelope([]byte(`{not json`)); err == nil {
		t.Fatal("DecodeEnvelope with malformed JSON: expected error, got nil")
	}
}

// TestEnvelope_IsHumanReadable pins the debuggability property the doc
// comment on Encode promises: a captured envelope must be readable without
// running it through this package's decoder.
func TestEnvelope_IsHumanReadable(t *testing.T) {
	e, err := NewMigratePrepare(1, 0, "hk-access-1", 1)
	if err != nil {
		t.Fatalf("NewMigratePrepare: %v", err)
	}
	encoded, err := e.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, want := range []string{`"type"`, `"MIGRATE_PREPARE"`, `"target_gateway"`, `"hk-access-1"`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("encoded envelope missing readable substring %q; got: %s", want, encoded)
		}
	}
}
