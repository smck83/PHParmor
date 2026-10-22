package config

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix prefixes every environment override. Nested keys are joined with
// "__", e.g. PHPARMOR_SERVER__READ_HEADER_TIMEOUT=5s. Lists of scalars take a
// comma-separated value. Control modes use PHPARMOR_CONTROLS__PA_FRAME=monitor
// (underscores in the ID stand for hyphens). Hosts cannot be set from env.
const EnvPrefix = "PHPARMOR_"

// EnvConfigPath names the config file path; it is read by main, not here.
const EnvConfigPath = EnvPrefix + "CONFIG"

const controlsEnvPrefix = EnvPrefix + "CONTROLS__"

var (
	durationType = reflect.TypeOf(time.Duration(0))
	byteSizeType = reflect.TypeOf(ByteSize(0))
	modeType     = reflect.TypeOf(Mode(""))
)

func applyEnv(cfg *Config, environ []string) error {
	vars := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, EnvPrefix) || k == EnvConfigPath {
			continue
		}
		vars[k] = v
	}
	if len(vars) == 0 {
		return nil
	}

	var errs []string
	for k, v := range vars {
		if !strings.HasPrefix(k, controlsEnvPrefix) {
			continue
		}
		id := strings.ReplaceAll(strings.TrimPrefix(k, controlsEnvPrefix), "_", "-")
		delete(vars, k)
		if !IsControl(id) {
			errs = append(errs, fmt.Sprintf("%s: unknown control %q", k, id))
			continue
		}
		m, err := ParseMode(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
			continue
		}
		cfg.Controls[id] = m
	}

	walkEnv(reflect.ValueOf(cfg).Elem(), EnvPrefix, vars, &errs)

	for k := range vars {
		errs = append(errs, fmt.Sprintf("%s: unknown setting", k))
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("env overrides:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// walkEnv sets every scalar field of v whose env key is present in vars, and
// removes consumed keys from vars.
func walkEnv(v reflect.Value, prefix string, vars map[string]string, errs *[]string) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		key := prefix + strings.ToUpper(tag)
		fv := v.Field(i)

		if fv.Kind() == reflect.Struct {
			walkEnv(fv, key+"__", vars, errs)
			continue
		}
		raw, ok := vars[key]
		if !ok {
			continue
		}
		delete(vars, key)
		if err := setScalar(fv, raw); err != nil {
			*errs = append(*errs, fmt.Sprintf("%s: %v", key, err))
		}
	}
}

func setScalar(v reflect.Value, s string) error {
	switch v.Type() {
	case durationType:
		d, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		v.SetInt(int64(d))
		return nil
	case byteSizeType:
		b, err := ParseByteSize(s)
		if err != nil {
			return err
		}
		v.SetInt(int64(b))
		return nil
	case modeType:
		m, err := ParseMode(s)
		if err != nil {
			return err
		}
		v.SetString(string(m))
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer: %w", err)
		}
		v.SetInt(n)
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("invalid bool: %w", err)
		}
		v.SetBool(b)
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("not settable from env")
		}
		var items []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				items = append(items, p)
			}
		}
		v.Set(reflect.ValueOf(items))
	default:
		return fmt.Errorf("not settable from env")
	}
	return nil
}
