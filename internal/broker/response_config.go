package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/kevinpinscoe/parzival/internal/consumer"
)

// configuredResponseValidator is a response validator that needs trusted,
// deployment-specific facts to do its job: the exact origin a returned URL
// must have, for example. Such facts are never compiled into the product.
// They come from the operation's response_config in the root-owned consumer
// definition (consumer.Operation.ResponseConfig), never from a client.
type configuredResponseValidator struct {
	// keys is the exact set of response_config keys the validator requires.
	// A missing key or an extra one refuses broker startup.
	keys []string
	// check validates the configured values themselves, at startup.
	check func(cfg map[string]string) error
	// validate canonicalizes raw stdout against the approved shape and the
	// trusted configuration, exactly as a responseValidator does.
	validate func(raw []byte, cfg map[string]string) (json.RawMessage, error)
}

// configuredResponseValidators is keyed by "<consumer>.<operation>", like
// responseValidators. A key must appear in at most one of the two maps.
var configuredResponseValidators = map[string]configuredResponseValidator{}

// errNoResponseValidator marks an operation with no approved response shape.
var errNoResponseValidator = errors.New("has no approved response validator")

// validatorFor returns the approved canonicalizer for the operation `name`,
// bound to op's trusted response_config. It is the one place both startup
// and request handling resolve a validator, so an operation the broker
// agreed to start with is validated the same way on every request.
//
//   - A configured validator requires op.ResponseConfig to hold exactly its
//     keys, with values its check accepts.
//   - A plain validator refuses any response_config: configuration that
//     nothing reads is an administrator's mistake, and silently ignoring it
//     would enforce less than was written.
func validatorFor(name string, op consumer.Operation) (responseValidator, error) {
	if cv, ok := configuredResponseValidators[name]; ok {
		if err := checkResponseConfigKeys(cv.keys, op.ResponseConfig); err != nil {
			return nil, err
		}
		cfg := make(map[string]string, len(op.ResponseConfig))
		for k, v := range op.ResponseConfig {
			cfg[k] = v
		}
		if err := cv.check(cfg); err != nil {
			return nil, fmt.Errorf("response_config: %w", err)
		}
		return func(raw []byte) (json.RawMessage, error) { return cv.validate(raw, cfg) }, nil
	}
	if v, ok := responseValidators[name]; ok {
		if len(op.ResponseConfig) != 0 {
			return nil, fmt.Errorf("response_config given, but this operation's validator takes none")
		}
		return v, nil
	}
	return nil, errNoResponseValidator
}

func checkResponseConfigKeys(want []string, got map[string]string) error {
	wantSet := make(map[string]bool, len(want))
	for _, k := range want {
		wantSet[k] = true
		if _, ok := got[k]; !ok {
			return fmt.Errorf("response_config is missing required key %q", k)
		}
	}
	extra := make([]string, 0)
	for k := range got {
		if !wantSet[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("response_config has unknown key(s) %q", extra)
	}
	return nil
}
