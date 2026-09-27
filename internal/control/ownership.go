package control

import (
	"encoding/json"
	"fmt"
)

type OwnershipRecord struct {
	Session string `json:"session"`
	Access  string `json:"access"`
	Egress  string `json:"egress"`
	Epoch   uint64 `json:"epoch"`
}

func (r OwnershipRecord) Validate() error {
	if r.Session == "" {
		return fmt.Errorf("control: OwnershipRecord.Session must not be empty")
	}
	if r.Access == "" {
		return fmt.Errorf("control: OwnershipRecord.Access must not be empty")
	}
	if r.Egress == "" {
		return fmt.Errorf("control: OwnershipRecord.Egress must not be empty")
	}
	return nil
}

func (r OwnershipRecord) NextEpoch(newEgress string) OwnershipRecord {
	r.Egress = newEgress
	r.Epoch++
	return r
}

func (r OwnershipRecord) Newer(existing OwnershipRecord) bool {
	return r.Epoch > existing.Epoch
}

const sessionKeyPrefix = "/egressa/session/"

func SessionKey(sessionID string) string {
	return sessionKeyPrefix + sessionID
}

func MarshalOwnership(r OwnershipRecord) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func UnmarshalOwnership(data []byte) (OwnershipRecord, error) {
	var r OwnershipRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return OwnershipRecord{}, fmt.Errorf("control: decoding OwnershipRecord: %w", err)
	}
	if err := r.Validate(); err != nil {
		return OwnershipRecord{}, err
	}
	return r, nil
}
