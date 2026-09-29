package control

import "testing"

func TestOwnershipRecord_Validate(t *testing.T) {
	valid := OwnershipRecord{Session: "s1", Access: "a1", Egress: "e1", Epoch: 0}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() on a well-formed record: %v", err)
	}

	cases := []OwnershipRecord{
		{Access: "a1", Egress: "e1"},
		{Session: "s1", Egress: "e1"},
		{Session: "s1", Access: "a1"},
	}
	for _, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error for a missing required field", c)
		}
	}
}

func TestOwnershipRecord_MarshalUnmarshal_RoundTrip(t *testing.T) {
	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "e1", Epoch: 7}
	data, err := MarshalOwnership(rec)
	if err != nil {
		t.Fatalf("MarshalOwnership: %v", err)
	}
	got, err := UnmarshalOwnership(data)
	if err != nil {
		t.Fatalf("UnmarshalOwnership: %v", err)
	}
	if got != rec {
		t.Fatalf("round-trip = %+v, want %+v", got, rec)
	}
}

func TestMarshalOwnership_RejectsInvalid(t *testing.T) {
	if _, err := MarshalOwnership(OwnershipRecord{Session: "s1"}); err == nil {
		t.Fatal("MarshalOwnership accepted a record missing Access/Egress")
	}
}

func TestUnmarshalOwnership_RejectsInvalid(t *testing.T) {
	if _, err := UnmarshalOwnership([]byte(`{"session":"","access":"a","egress":"e"}`)); err == nil {
		t.Fatal("UnmarshalOwnership accepted a record with an empty Session")
	}
	if _, err := UnmarshalOwnership([]byte(`not json`)); err == nil {
		t.Fatal("UnmarshalOwnership accepted malformed JSON")
	}
}

func TestOwnershipRecord_NextEpoch(t *testing.T) {
	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 3}
	next := rec.NextEpoch("sg")
	if next.Epoch != 4 {
		t.Fatalf("NextEpoch().Epoch = %d, want 4", next.Epoch)
	}
	if next.Egress != "sg" {
		t.Fatalf("NextEpoch().Egress = %q, want %q", next.Egress, "sg")
	}
	if rec.Epoch != 3 || rec.Egress != "hk" {
		t.Fatalf("NextEpoch mutated the receiver: %+v", rec)
	}
}

func TestOwnershipRecord_NextAccessEpoch(t *testing.T) {
	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 3}
	next := rec.NextAccessEpoch("a2")
	if next.Epoch != 4 {
		t.Fatalf("NextAccessEpoch().Epoch = %d, want 4", next.Epoch)
	}
	if next.Access != "a2" {
		t.Fatalf("NextAccessEpoch().Access = %q, want %q", next.Access, "a2")
	}
	if next.Egress != "hk" {
		t.Fatalf("NextAccessEpoch().Egress = %q, want unchanged %q (access handoff must not touch egress)", next.Egress, "hk")
	}
	if rec.Epoch != 3 || rec.Access != "a1" {
		t.Fatalf("NextAccessEpoch mutated the receiver: %+v", rec)
	}
}

func TestOwnershipRecord_Newer(t *testing.T) {
	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 5}
	cases := []struct {
		name  string
		other OwnershipRecord
		want  bool
	}{
		{"strictly greater epoch is newer", OwnershipRecord{Epoch: 6}, true},
		{"equal epoch is not newer", OwnershipRecord{Epoch: 5}, false},
		{"lower epoch is not newer", OwnershipRecord{Epoch: 4}, false},
	}
	for _, c := range cases {
		if got := c.other.Newer(base); got != c.want {
			t.Errorf("%s: Newer() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSessionKey_NamespacesByPrefix(t *testing.T) {
	k := SessionKey("abc")
	if k != "/egressa/session/abc" {
		t.Fatalf("SessionKey(%q) = %q, want %q", "abc", k, "/egressa/session/abc")
	}
}
