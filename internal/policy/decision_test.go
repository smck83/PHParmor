package policy

import (
	"testing"

	"github.com/smck83/phparmor/internal/config"
)

func TestEvaluate(t *testing.T) {
	v := &Violation{Reason: "too_many", Status: 431}
	tests := []struct {
		name      string
		mode      config.Mode
		v         *Violation
		ok, block bool
		outcome   Outcome
	}{
		{"off ignores violation", config.ModeOff, v, false, false, ""},
		{"enforce pass", config.ModeEnforce, nil, true, false, Pass},
		{"enforce violation blocks", config.ModeEnforce, v, true, true, Block},
		{"monitor pass", config.ModeMonitor, nil, true, false, Pass},
		{"monitor violation forwards", config.ModeMonitor, v, true, false, WouldBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, block, ok := Evaluate("PA-X", tt.mode, tt.v)
			if ok != tt.ok || block != tt.block || d.Outcome != tt.outcome {
				t.Fatalf("got %+v block=%v ok=%v", d, block, ok)
			}
			if ok && (d.Control != "PA-X" || d.Mode != tt.mode) {
				t.Errorf("decision = %+v", d)
			}
			if tt.v != nil && ok && d.Reason != "too_many" {
				t.Errorf("reason = %q", d.Reason)
			}
		})
	}
}
