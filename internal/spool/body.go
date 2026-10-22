package spool

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
)

// Pool owns the memory budget, the disk quota and the spool directory.
type Pool struct {
	dir        string
	mem        *Budget
	disk       *Budget
	perRequest atomic.Int64
	bypass     atomic.Bool
}

// PoolOptions configures a Pool.
type PoolOptions struct {
	Dir          string
	PerRequest   int64 // memory used by one body before it spills to disk
	MemoryGlobal int64
	DiskQuota    int64
	Bypass       bool // on_overload: bypass
}

// NewPool returns a pool. Dir must exist and be writable.
func NewPool(o PoolOptions) *Pool {
	p := &Pool{dir: o.Dir, mem: NewBudget(o.MemoryGlobal), disk: NewBudget(o.DiskQuota)}
	p.Configure(o)
	return p
}

// Configure applies reloadable settings. Dir is fixed for the pool's life.
func (p *Pool) Configure(o PoolOptions) {
	p.perRequest.Store(o.PerRequest)
	p.mem.SetLimit(o.MemoryGlobal)
	p.disk.SetLimit(o.DiskQuota)
	p.bypass.Store(o.Bypass)
}

// MemoryInFlight returns the memory bytes currently reserved.
func (p *Pool) MemoryInFlight() int64 { return p.mem.InFlight() }

// DiskInFlight returns the spool bytes currently reserved.
func (p *Pool) DiskInFlight() int64 { return p.disk.InFlight() }

func (p *Pool) reserve(b *Budget, n int64) bool {
	if p.bypass.Load() {
		b.Acquire(n)
		return true
	}
	return b.TryAcquire(n)
}

// Body is a write-once, read-many request body held in memory until it
// outgrows the per-request threshold, then in a temp file. Close must be
// called once the body is no longer needed; it returns all reserved budget
// and removes the temp file.
type Body struct {
	pool *Pool
	max  int64

	mem         []byte
	memReserved int64

	f            *os.File
	diskReserved int64

	size   int64
	closed bool
}

// NewBody returns an empty body that accepts at most max bytes.
func (p *Pool) NewBody(max int64) *Body { return &Body{pool: p, max: max} }

// Size returns the bytes written so far.
func (b *Body) Size() int64 { return b.size }

// Spilled reports whether the body moved to disk.
func (b *Body) Spilled() bool { return b.f != nil }

// Write appends p. It fails with ErrTooLarge past the body maximum and with
// ErrOverloaded when the memory budget or disk quota is exhausted (unless
// the pool is in bypass mode).
func (b *Body) Write(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("spool: write to closed body")
	}
	n := int64(len(p))
	if b.size+n > b.max {
		return 0, ErrTooLarge
	}
	if b.f == nil && b.size+n <= b.pool.perRequest.Load() {
		if err := b.growMem(b.size + n); err != nil {
			return 0, err
		}
		b.mem = append(b.mem, p...)
		b.size += n
		return len(p), nil
	}
	if b.f == nil {
		if err := b.spill(); err != nil {
			return 0, err
		}
	}
	if !b.pool.reserve(b.pool.disk, n) {
		return 0, ErrOverloaded
	}
	b.diskReserved += n
	w, err := b.f.Write(p)
	b.size += int64(w)
	if err != nil {
		return w, fmt.Errorf("spool: write: %w", err)
	}
	return w, nil
}

// growMem makes sure the in-memory buffer can hold need bytes, reserving
// budget for the whole capacity so the accounting matches real memory.
func (b *Body) growMem(need int64) error {
	if need <= int64(cap(b.mem)) {
		return nil
	}
	newCap := 2 * int64(cap(b.mem))
	if newCap < 4096 {
		newCap = 4096
	}
	if newCap < need {
		newCap = need
	}
	if limit := b.pool.perRequest.Load(); newCap > limit {
		newCap = limit
	}
	delta := newCap - int64(cap(b.mem))
	if !b.pool.reserve(b.pool.mem, delta) {
		return ErrOverloaded
	}
	b.memReserved += delta
	next := make([]byte, len(b.mem), newCap)
	copy(next, b.mem)
	b.mem = next
	return nil
}

// spill moves the in-memory content to a new temp file.
func (b *Body) spill() error {
	if !b.pool.reserve(b.pool.disk, b.size) {
		return ErrOverloaded
	}
	b.diskReserved += b.size
	f, err := os.CreateTemp(b.pool.dir, "body-*") // created 0600
	if err != nil {
		return fmt.Errorf("spool: create temp file: %w", err)
	}
	b.f = f
	if _, err := f.Write(b.mem); err != nil {
		return fmt.Errorf("spool: write: %w", err)
	}
	b.pool.mem.Release(b.memReserved)
	b.memReserved = 0
	b.mem = nil
	return nil
}

// ReadFrom copies r into the body until EOF.
func (b *Body) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := b.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// Reader returns a reader over the whole body from the start. Each call
// returns an independent reader.
func (b *Body) Reader() io.ReadSeeker {
	if b.f != nil {
		return io.NewSectionReader(b.f, 0, b.size)
	}
	return bytes.NewReader(b.mem)
}

// Close releases the body's budget and removes its temp file. It is safe to
// call more than once.
func (b *Body) Close() error {
	if b == nil || b.closed {
		return nil
	}
	b.closed = true
	b.pool.mem.Release(b.memReserved)
	b.pool.disk.Release(b.diskReserved)
	b.memReserved, b.diskReserved, b.mem = 0, 0, nil
	if b.f == nil {
		return nil
	}
	name := b.f.Name()
	err := b.f.Close()
	if rerr := os.Remove(name); rerr != nil {
		err = errors.Join(err, rerr)
	}
	if err != nil {
		return fmt.Errorf("spool: remove temp file: %w", err)
	}
	return nil
}
