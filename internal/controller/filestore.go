package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ngthdong/egressa/internal/control"
)

// FileStore is a control.MemStore that is saved to a JSON file after
// every write, so a single controller keeps its sessions across restarts
// without running etcd. Writes are rare (a gateway joining, a session
// opening or migrating), so rewriting the whole file each time is cheap.
type FileStore struct {
	*control.MemStore
	path string
	mu   sync.Mutex // serializes saves
}

var (
	_ control.KVStore = (*FileStore)(nil)
	_ control.Fencer  = (*FileStore)(nil)
)

// OpenFileStore loads path if it exists.
func OpenFileStore(path string) (*FileStore, error) {
	fs := &FileStore{MemStore: control.NewMemStore(), path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fs, nil
	}
	if err != nil {
		return nil, fmt.Errorf("controller: read state file: %w", err)
	}
	var kv map[string]json.RawMessage
	if err := json.Unmarshal(data, &kv); err != nil {
		return nil, fmt.Errorf("controller: parse state file %s: %w", path, err)
	}
	for k, v := range kv {
		if err := fs.MemStore.Put(context.Background(), k, v); err != nil {
			return nil, err
		}
	}
	return fs, nil
}

func (f *FileStore) save(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.List(ctx, "")
	if err != nil {
		return err
	}
	kv := make(map[string]json.RawMessage, len(all))
	for k, v := range all {
		kv[k] = v
	}
	data, err := json.MarshalIndent(kv, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".egressa-state-*")
	if err != nil {
		return fmt.Errorf("controller: save state: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("controller: save state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("controller: save state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("controller: save state: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.path); err != nil {
		return fmt.Errorf("controller: save state: %w", err)
	}
	return nil
}

// Put stores value and saves the file.
func (f *FileStore) Put(ctx context.Context, key string, value []byte) error {
	if err := f.MemStore.Put(ctx, key, value); err != nil {
		return err
	}
	return f.save(ctx)
}

// CompareAndSwap swaps as control.MemStore does and saves the file.
func (f *FileStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	rev, ok, err := f.MemStore.CompareAndSwap(ctx, key, expectedRevision, value)
	if err != nil || !ok {
		return rev, ok, err
	}
	return rev, ok, f.save(ctx)
}
