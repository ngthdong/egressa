package control

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ngthdong/egressa/internal/measurement"
)

type PolicyDocument struct {
	Version   uint64                      `json:"version"`
	Cost      measurement.CostWeights     `json:"cost"`
	Decision  measurement.DecisionWeights `json:"decision"`
	FlapGuard measurement.FlapGuardConfig `json:"flap_guard"`
}

var DefaultPolicyDocument = PolicyDocument{
	Version:   0,
	Cost:      measurement.DefaultCostWeights,
	Decision:  measurement.DefaultDecisionWeights,
	FlapGuard: measurement.DefaultFlapGuardConfig,
}

func (doc PolicyDocument) NextVersion() PolicyDocument {
	doc.Version++
	return doc
}

const policyKey = "/egressa/policy/current"

func MarshalPolicy(doc PolicyDocument) ([]byte, error) {
	return json.Marshal(doc)
}

func UnmarshalPolicy(data []byte) (PolicyDocument, error) {
	var doc PolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return PolicyDocument{}, fmt.Errorf("control: decoding PolicyDocument: %w", err)
	}
	return doc, nil
}

type PolicyService struct {
	store KVStore
}

func NewPolicyService(store KVStore) *PolicyService {
	return &PolicyService{store: store}
}

func (s *PolicyService) Set(ctx context.Context, doc PolicyDocument) error {
	data, err := MarshalPolicy(doc)
	if err != nil {
		return err
	}
	return s.store.Put(ctx, policyKey, data)
}

func (s *PolicyService) Get(ctx context.Context) (PolicyDocument, error) {
	data, found, err := s.store.Get(ctx, policyKey)
	if err != nil {
		return PolicyDocument{}, err
	}
	if !found {
		return DefaultPolicyDocument, nil
	}
	return UnmarshalPolicy(data)
}

func (s *PolicyService) Watch(ctx context.Context) (<-chan PolicyDocument, error) {
	events, err := s.store.Watch(ctx, policyKey)
	if err != nil {
		return nil, err
	}
	out := make(chan PolicyDocument)
	go func() {
		defer close(out)
		for ev := range events {
			if ev.Deleted {
				continue
			}
			doc, err := UnmarshalPolicy(ev.Value)
			if err != nil {
				continue
			}
			select {
			case out <- doc:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
