// Package spool buffers request bodies in memory and then on disk, under a
// global memory budget and a spool directory quota (SPEC section 6.5).
package spool

import (
	"errors"
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
	// ErrTooLarge means the body exceeded its maximum size.
	ErrTooLarge = errors.New("body exceeds maximum size")
	// ErrOverloaded means the memory budget or spool quota had no room.
	ErrOverloaded = errors.New("buffer budget exhausted")
)
