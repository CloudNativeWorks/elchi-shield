package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// supportedExts are the file extensions ReadDir/Parse recognize.
var supportedExts = map[string]struct{}{
	".yaml": {},
	".yml":  {},
	".json": {},
}

// isConfigFile reports whether path has a recognized config extension.
func isConfigFile(path string) bool {
	_, ok := supportedExts[strings.ToLower(filepath.Ext(path))]
	return ok
}

// Parse decodes a single config file's bytes into a *File using strict decoding
// (unknown fields are rejected) so misconfiguration surfaces immediately rather
// than being silently ignored. The format is chosen by file extension; .json is
// parsed as JSON, everything else as YAML (YAML is a JSON superset).
func Parse(file string, data []byte) (*File, error) {
	var f File
	ext := strings.ToLower(filepath.Ext(file))

	switch ext {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return nil, newFileError(file, "", fmt.Errorf("parse json: %w", err))
		}
		if err := ensureEOF(dec); err != nil {
			return nil, newFileError(file, "", err)
		}
	default:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return nil, newFileError(file, "", fmt.Errorf("parse yaml: %w", err))
		}
	}

	return &f, nil
}

// ensureEOF rejects trailing content after the first JSON document so files
// can't smuggle a second, ignored object.
func ensureEOF(dec *json.Decoder) error {
	if dec.More() {
		return errors.New("unexpected trailing content after first JSON document")
	}
	return nil
}
