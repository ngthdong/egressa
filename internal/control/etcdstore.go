//go:build etcd

package control

import (
	"context"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdStore implements KVStore and Fencer using an etcd v3 client.
// It translates store and fencing operations into etcd KV, watch, lease,
// and transaction APIs. Consistency, replication, and concurrency control
// are provided by the etcd cluster.
type EtcdStore struct {
	client *clientv3.Client
}

func NewEtcdStore(client *clientv3.Client) *EtcdStore {
	return &EtcdStore{client: client}
}

func (e *EtcdStore) Put(ctx context.Context, key string, value []byte) error {
	_, err := e.client.Put(ctx, key, string(value))
	if err != nil {
		return fmt.Errorf("control: etcd put %q: %w", key, err)
	}
	return nil
}

func (e *EtcdStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	resp, err := e.client.Get(ctx, key)
	if err != nil {
		return nil, false, fmt.Errorf("control: etcd get %q: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return nil, false, nil
	}
	return resp.Kvs[0].Value, true, nil
}

func (e *EtcdStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	resp, err := e.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("control: etcd list %q: %w", prefix, err)
	}
	out := make(map[string][]byte, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		out[string(kv.Key)] = kv.Value
	}
	return out, nil
}

func (e *EtcdStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	watchCh := e.client.Watch(ctx, prefix, clientv3.WithPrefix())
	out := make(chan Event)
	go func() {
		defer close(out)
		for resp := range watchCh {
			for _, ev := range resp.Events {
				out2 := Event{Key: string(ev.Kv.Key)}
				switch ev.Type {
				case clientv3.EventTypeDelete:
					out2.Deleted = true
				default:
					out2.Value = ev.Kv.Value
				}
				select {
				case out <- out2:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func (e *EtcdStore) Revision(ctx context.Context, key string) (int64, bool, error) {
	resp, err := e.client.Get(ctx, key)
	if err != nil {
		return 0, false, fmt.Errorf("control: etcd revision %q: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return 0, false, nil
	}
	return resp.Kvs[0].ModRevision, true, nil
}

func (e *EtcdStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	var cmp clientv3.Cmp
	if expectedRevision == 0 {
		cmp = clientv3.Compare(clientv3.CreateRevision(key), "=", 0)
	} else {
		cmp = clientv3.Compare(clientv3.ModRevision(key), "=", expectedRevision)
	}

	resp, err := e.client.Txn(ctx).
		If(cmp).
		Then(clientv3.OpPut(key, string(value))).
		Else(clientv3.OpGet(key)).
		Commit()
	if err != nil {
		return 0, false, fmt.Errorf("control: etcd compare-and-swap %q: %w", key, err)
	}
	if !resp.Succeeded {
		var cur int64
		if len(resp.Responses) > 0 {
			if getResp := resp.Responses[0].GetResponseRange(); getResp != nil && len(getResp.Kvs) > 0 {
				cur = getResp.Kvs[0].ModRevision
			}
		}
		return cur, false, nil
	}
	return resp.Header.Revision, true, nil
}

// PutWithLease stores value under key and attaches it to an existing etcd
// lease. The key is removed automatically when the lease expires.
func (e *EtcdStore) PutWithLease(ctx context.Context, key string, value []byte, leaseID clientv3.LeaseID) error {
	_, err := e.client.Put(ctx, key, string(value), clientv3.WithLease(leaseID))
	if err != nil {
		return fmt.Errorf("control: etcd put-with-lease %q: %w", key, err)
	}
	return nil
}
