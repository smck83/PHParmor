// Package spool buffers request bodies under a global byte budget.
//
// M1 buffers bodies in memory only. The disk spool (SPEC section 6.5) lands
// in M3 and will draw on the same Budget.
package spool

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

// Budget is a global in-flight byte budget shared by all requests.
type Budget struct {
	limit atomic.Int64
	used  atomic.Int64
}

// NewBudget returns a budget of limit bytes.
func NewBudget(limit int64) *Budget {
	b := &Budget{}
	b.limit.Store(limit)
	return b
}

// SetLimit changes the limit. Bytes already reserved are unaffected.
func (b *Budget) SetLimit(limit int64) { b.limit.Store(limit) }

// TryAcquire reserves n bytes if they fit under the limit.
func (b *Budget) TryAcquire(n int64) bool {
	for {
		used := b.used.Load()
		if used+n > b.limit.Load() {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

// Acquire reserves n bytes regardless of the limit (on_overload: bypass).
func (b *Budget) Acquire(n int64) { b.used.Add(n) }

// Release returns n reserved bytes.
func (b *Budget) Release(n int64) { b.used.Add(-n) }

// InFlight returns the bytes currently reserved.
func (b *Budget) InFlight() int64 { return b.used.Load() }

var (
	// ErrTooLarge means the body exceeded the per-request maximum.
	ErrTooLarge = errors.New("body exceeds maximum size")
	// ErrOverloaded means the global budget had no room for the body.
	ErrOverloaded = errors.New("global buffer budget exhausted")
)

const chunkSize = 32 << 10

// Buffer is a request body held in memory. Release must be called once the
// body is no longer needed.
type Buffer struct {
	Data     []byte
	budget   *Budget
	reserved int64
}

// Release returns the buffer's bytes to the budget.
func (b *Buffer) Release() {
	if b == nil || b.budget == nil {
		return
	}
	b.budget.Release(b.reserved)
	b.reserved = 0
	b.Data = nil
}

// ReadOptions controls ReadAll.
type ReadOptions struct {
	// Max is the largest body accepted, in bytes.
	Max int64
	// SizeHint is the declared Content-Length, or -1 if unknown.
	SizeHint int64
	// Bypass reserves budget even when the limit is exceeded.
	Bypass bool
	// BeforeRead is called with the bytes read so far before each read. It
	// is used to enforce a minimum transfer rate.
	BeforeRead func(n int64)
}

// ReadAll reads r fully into memory, reserving budget as it grows. On error
// all reserved budget is returned.
func ReadAll(r io.Reader, b *Budget, o ReadOptions) (*Buffer, error) {
	if o.SizeHint > o.Max {
		return nil, ErrTooLarge
	}
	buf := &Buffer{budget: b}
	reserve := func(n int64) bool {
		if o.Bypass {
			b.Acquire(n)
		} else if !b.TryAcquire(n) {
			return false
		}
		buf.reserved += n
		return true
	}

	initial := int64(chunkSize)
	if o.SizeHint >= 0 {
		// One spare byte lets the final read see EOF without growing.
		initial = o.SizeHint + 1
	}
	if initial > o.Max+1 {
		initial = o.Max + 1
	}
	if !reserve(initial) {
		return nil, ErrOverloaded
	}
	buf.Data = make([]byte, 0, initial)

	for {
		if int64(len(buf.Data)) > o.Max {
			buf.Release()
			return nil, ErrTooLarge
		}
		if len(buf.Data) == cap(buf.Data) {
			grow := int64(cap(buf.Data))
			if grow < chunkSize {
				grow = chunkSize
			}
			if rem := o.Max + 1 - int64(cap(buf.Data)); grow > rem {
				grow = rem
			}
			if !reserve(grow) {
				buf.Release()
				return nil, ErrOverloaded
			}
			next := make([]byte, len(buf.Data), int64(cap(buf.Data))+grow)
			copy(next, buf.Data)
			buf.Data = next
		}
		if o.BeforeRead != nil {
			o.BeforeRead(int64(len(buf.Data)))
		}
		n, err := r.Read(buf.Data[len(buf.Data):cap(buf.Data)])
		buf.Data = buf.Data[:len(buf.Data)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			buf.Release()
			return nil, fmt.Errorf("read body: %w", err)
		}
	}
	if int64(len(buf.Data)) > o.Max {
		buf.Release()
		return nil, ErrTooLarge
	}
	return buf, nil
}
