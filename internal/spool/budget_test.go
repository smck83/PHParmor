package spool

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestReadAll(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 100<<10)
	tests := []struct {
		name    string
		data    []byte
		hint    int64
		max     int64
		budget  int64
		bypass  bool
		wantErr error
	}{
		{"known length", body, int64(len(body)), 1 << 20, 1 << 20, false, nil},
		{"unknown length", body, -1, 1 << 20, 1 << 20, false, nil},
		{"empty", nil, -1, 10, 1 << 20, false, nil},
		{"exactly max", body, -1, int64(len(body)), 1 << 20, false, nil},
		{"declared over max", body, int64(len(body)), 10, 1 << 20, false, ErrTooLarge},
		{"streamed over max", body, -1, 1000, 1 << 20, false, ErrTooLarge},
		{"lying short length", body, 10, 1 << 20, 1 << 20, false, nil},
		{"budget exhausted up front", body, int64(len(body)), 1 << 20, 1000, false, ErrOverloaded},
		{"budget exhausted while growing", body, -1, 1 << 20, 50 << 10, false, ErrOverloaded},
		{"bypass ignores budget", body, -1, 1 << 20, 10, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBudget(tt.budget)
			buf, err := ReadAll(iotest.HalfReader(bytes.NewReader(tt.data)), b, ReadOptions{Max: tt.max, SizeHint: tt.hint, Bypass: tt.bypass})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				if b.InFlight() != 0 {
					t.Errorf("budget leaked %d bytes on error", b.InFlight())
				}
				return
			}
			if !bytes.Equal(buf.Data, tt.data) {
				t.Errorf("data mismatch: got %d bytes", len(buf.Data))
			}
			if b.InFlight() < int64(len(tt.data)) {
				t.Errorf("reserved %d < %d", b.InFlight(), len(tt.data))
			}
			buf.Release()
			buf.Release()
			if b.InFlight() != 0 {
				t.Errorf("budget not returned: %d", b.InFlight())
			}
		})
	}
}

func TestReadAllReadError(t *testing.T) {
	b := NewBudget(1 << 20)
	_, err := ReadAll(iotest.ErrReader(io.ErrUnexpectedEOF), b, ReadOptions{Max: 100, SizeHint: -1})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v", err)
	}
	if b.InFlight() != 0 {
		t.Errorf("budget leaked")
	}
}

func TestReadAllCallsBeforeRead(t *testing.T) {
	var calls int
	_, err := ReadAll(bytes.NewReader([]byte("hello")), NewBudget(1<<20), ReadOptions{
		Max: 100, SizeHint: 5, BeforeRead: func(int64) { calls++ },
	})
	if err != nil || calls == 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
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
