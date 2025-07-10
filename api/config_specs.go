package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

var ConfigSpecBase = "eth/v1/config/spec"

func (c *Client) GetConfigSpecs(ctx context.Context) (map[string]any, error) {
	var configSpecs map[string]any
	resp, err := c.get(ctx, c.cfg.QueryTimeout, ConfigSpecBase, "")
	if err != nil {
		return nil, errors.Wrap(err, "requesting config-specs")
	}
	err = json.Unmarshal(resp, &configSpecs)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling config-specs from http request")
	}

	return parseSpecMap(configSpecs["data"].(map[string]any)), nil
}

func parseSpecMap(data map[string]any) map[string]any {
	config := make(map[string]any)
	for k, v := range data {
		switch value := v.(type) {
		case string:
			config[k] = parseSpecString(k, value)
		case []any:
			config[k] = parseSpecArray(value)
		case map[string]any:
			config[k] = parseSpecMap(value)
		default:
			config[k] = v
		}
	}

	return config
}

func parseSpecArray(array []any) []any {
	result := make([]any, len(array))
	for i, element := range array {
		switch value := element.(type) {
		case string:
			result[i] = parseSpecString("", value)
		case []any:
			result[i] = parseSpecArray(value)
		case map[string]any:
			result[i] = parseSpecMap(value)
		default:
			result[i] = element
		}
	}

	return result
}

func parseSpecString(k, v string) any {
	// Handle domains.
	if strings.HasPrefix(k, "DOMAIN_") {
		byteVal, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err == nil {
			var domainType phase0.DomainType
			copy(domainType[:], byteVal)

			return domainType
		}
	}

	// Handle fork versions.
	if strings.HasSuffix(k, "_FORK_VERSION") {
		byteVal, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err == nil {
			var version phase0.Version
			copy(version[:], byteVal)

			return version
		}
	}

	// Handle hex strings.
	if strings.HasPrefix(v, "0x") {
		byteVal, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err == nil {
			return byteVal
		}
	}

	// Handle times.
	if strings.HasSuffix(k, "_TIME") {
		intVal, err := strconv.ParseInt(v, 10, 64)
		if err == nil && intVal != 0 {
			return time.Unix(intVal, 0)
		}
	}

	// Handle durations.
	if strings.HasPrefix(k, "SECONDS_PER_") || k == "GENESIS_DELAY" {
		intVal, err := strconv.ParseInt(v, 10, 64)
		if err == nil && intVal >= 0 {
			return time.Duration(intVal) * time.Second
		}
	}

	// Handle integers.
	if v == "0" {
		return uint64(0)
	}
	intVal, err := strconv.ParseUint(v, 10, 64)
	if err == nil && intVal != 0 {
		return intVal
	}

	// Assume string.
	return v
}
