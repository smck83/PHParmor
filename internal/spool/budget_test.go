package spool

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"testing/iotest"
)

func newPool(t *testing.T, o PoolOptions) *Pool {
	t.Helper()
	if o.Dir == "" {
		o.Dir = t.TempDir()
	}
	return NewPool(o)
}

func spoolFiles(t *testing.T, dir string) int {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

func TestBodyMemoryAndSpill(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 8<<10) // 128 KiB
	tests := []struct {
		name        string
		perRequest  int64
		wantSpilled bool
	}{
		{"fits in memory", 1 << 20, false},
		{"spills to disk", 16 << 10, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := newPool(t, PoolOptions{Dir: dir, PerRequest: tt.perRequest, MemoryGlobal: 1 << 20, DiskQuota: 1 << 20})
			b := p.NewBody(1 << 20)
			if _, err := b.ReadFrom(iotest.HalfReader(bytes.NewReader(data))); err != nil {
				t.Fatal(err)
			}
			if b.Spilled() != tt.wantSpilled || b.Size() != int64(len(data)) {
				t.Fatalf("spilled=%v size=%d", b.Spilled(), b.Size())
			}
			for i := 0; i < 2; i++ { // readers are independent
				got, err := io.ReadAll(b.Reader())
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("read %d: %d bytes, %v", i, len(got), err)
				}
			}
			if tt.wantSpilled {
				if p.MemoryInFlight() != 0 || p.DiskInFlight() != int64(len(data)) {
					t.Errorf("after spill mem=%d disk=%d", p.MemoryInFlight(), p.DiskInFlight())
				}
				if spoolFiles(t, dir) != 1 {
					t.Errorf("expected one spool file")
				}
				fi, err := os.Stat(b.f.Name())
				if err != nil {
					t.Fatal(err)
				}
				if perm := fi.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
					t.Errorf("spool file mode %v, want 0600", perm)
				}
			} else if p.MemoryInFlight() < int64(len(data)) {
				t.Errorf("memory reserved %d < %d", p.MemoryInFlight(), len(data))
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			if p.MemoryInFlight() != 0 || p.DiskInFlight() != 0 || spoolFiles(t, dir) != 0 {
				t.Errorf("not cleaned up: mem=%d disk=%d files=%d", p.MemoryInFlight(), p.DiskInFlight(), spoolFiles(t, dir))
			}
		})
	}
}

func TestBodyLimits(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 64<<10)
	tests := []struct {
		name string
		o    PoolOptions
		max  int64
		want error
	}{
		{"over body max", PoolOptions{PerRequest: 1 << 20, MemoryGlobal: 1 << 20, DiskQuota: 1 << 20}, 1000, ErrTooLarge},
		{"memory budget exhausted", PoolOptions{PerRequest: 1 << 20, MemoryGlobal: 8 << 10, DiskQuota: 1 << 20}, 1 << 20, ErrOverloaded},
		{"disk quota exhausted", PoolOptions{PerRequest: 4 << 10, MemoryGlobal: 1 << 20, DiskQuota: 16 << 10}, 1 << 20, ErrOverloaded},
		{"bypass ignores budgets", PoolOptions{PerRequest: 4 << 10, MemoryGlobal: 1, DiskQuota: 1, Bypass: true}, 1 << 20, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.o.Dir = dir
			p := newPool(t, tt.o)
			b := p.NewBody(tt.max)
			_, err := b.ReadFrom(bytes.NewReader(data))
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			_ = b.Close()
			if p.MemoryInFlight() != 0 || p.DiskInFlight() != 0 || spoolFiles(t, dir) != 0 {
				t.Errorf("leaked: mem=%d disk=%d files=%d", p.MemoryInFlight(), p.DiskInFlight(), spoolFiles(t, dir))
			}
		})
	}
}

func TestBodyReadError(t *testing.T) {
	p := newPool(t, PoolOptions{PerRequest: 1 << 20, MemoryGlobal: 1 << 20, DiskQuota: 1 << 20})
	b := p.NewBody(1 << 20)
	if _, err := b.ReadFrom(iotest.ErrReader(io.ErrUnexpectedEOF)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v", err)
	}
	_ = b.Close()
	if _, err := b.Write([]byte("x")); err == nil {
		t.Error("write after close accepted")
	}
}

func TestBudget(t *testing.T) {
	b := NewBudget(10)
	if !b.TryAcquire(6) || b.TryAcquire(5) || !b.TryAcquire(4) {
		t.Fatal("unexpected acquire results")
	}
	b.Release(10)
	b.SetLimit(3)
	if b.TryAcquire(4) {
		t.Fatal("limit not lowered")
	}
}
