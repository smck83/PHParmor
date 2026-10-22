package policy

import "github.com/smck83/phparmor/internal/config"

// Violation is what a check reports when a request breaks a rule. Reason is
// a short fixed identifier (never request data); Status is the response
// status used when the control is enforced (SPEC section 4.1).
type Violation struct {
	Reason string
	Status int
}

// Evaluate turns a check result into a decision for a control in the given
// mode. v is nil when the check passed. block is true only when the control
// is enforced and the check failed. ok is false when the control is off, in
// which case no decision is recorded.
func Evaluate(control string, mode config.Mode, v *Violation) (d Decision, block, ok bool) {
	switch {
	case mode == config.ModeOff:
		return Decision{}, false, false
	case v == nil:
		return Decision{Control: control, Mode: mode, Outcome: Pass}, false, true
	case mode == config.ModeEnforce:
		return Decision{Control: control, Mode: mode, Outcome: Block, Reason: v.Reason}, true, true
	default:
		return Decision{Control: control, Mode: mode, Outcome: WouldBlock, Reason: v.Reason}, false, true
	}
}
