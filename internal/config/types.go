package config

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is the operating mode of a control.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeMonitor Mode = "monitor"
	ModeOff     Mode = "off"
)

// ParseMode parses a control mode.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.TrimSpace(s)); m {
	case ModeEnforce, ModeMonitor, ModeOff:
		return m, nil
	default:
		return "", fmt.Errorf("invalid mode %q (want enforce, monitor or off)", s)
	}
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (m *Mode) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: mode must be a scalar", n.Line)
	}
	v, err := ParseMode(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*m = v
	return nil
}

// ByteSize is a size in bytes. In YAML and env vars it accepts a plain integer
// or an integer with a B, KiB, MiB or GiB suffix.
type ByteSize int64

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	{"GiB", 1 << 30},
	{"MiB", 1 << 20},
	{"KiB", 1 << 10},
	{"B", 1},
}

// ParseByteSize parses values such as "32MiB", "8KiB" or "4096".
func ParseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	num := s
	for _, u := range byteUnits {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			num = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid byte size %q (want e.g. 4096, 8KiB, 32MiB, 2GiB)", s)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("byte size %q is too large", s)
	}
	return ByteSize(n * mult), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: byte size must be a scalar", n.Line)
	}
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = v
	return nil
}

// String formats the size using the largest exact unit.
func (b ByteSize) String() string {
	for _, u := range byteUnits {
		if u.mult > 1 && int64(b)%u.mult == 0 && b != 0 {
			return strconv.FormatInt(int64(b)/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(int64(b), 10)
}
