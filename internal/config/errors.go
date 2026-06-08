package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// FileError attributes an error to a specific config file and, when known, a
// field path within it. It makes reload failures actionable.
type FileError struct {
	File  string // source file path
	Field string // dotted field path, e.g. "domains[2].routes[0].match.path_regex"
	Err   error
}

func (e *FileError) Error() string {
	switch {
	case e.File != "" && e.Field != "":
		return fmt.Sprintf("%s: %s: %v", e.File, e.Field, e.Err)
	case e.File != "":
		return fmt.Sprintf("%s: %v", e.File, e.Err)
	default:
		return e.Err.Error()
	}
}

func (e *FileError) Unwrap() error { return e.Err }

// newFileError builds a *FileError; field may be empty.
func newFileError(file, field string, err error) *FileError {
	return &FileError{File: file, Field: field, Err: err}
}

// MultiError aggregates multiple errors (typically one per offending file or
// field) so a single reload reports every problem at once instead of failing on
// the first. The zero value is ready to use.
type MultiError struct {
	Errors []error
}

// Add appends err if non-nil.
func (m *MultiError) Add(err error) {
	if err != nil {
		m.Errors = append(m.Errors, err)
	}
}

// ErrorOrNil returns m as an error, or nil when no errors were collected.
func (m *MultiError) ErrorOrNil() error {
	if m == nil || len(m.Errors) == 0 {
		return nil
	}
	return m
}

func (m *MultiError) Error() string {
	msgs := make([]string, 0, len(m.Errors))
	for _, e := range m.Errors {
		msgs = append(msgs, e.Error())
	}
	// Stable, readable output regardless of collection order.
	sort.Strings(msgs)
	if len(msgs) == 1 {
		return msgs[0]
	}
	return fmt.Sprintf("%d config errors:\n  - %s", len(msgs), strings.Join(msgs, "\n  - "))
}

// Unwrap exposes the aggregated errors to errors.Is/As.
func (m *MultiError) Unwrap() []error { return m.Errors }

// ErrEmptyConfigDir is returned (wrapped) by Load when the directory contains
// no config files. Callers use errors.Is to distinguish "no config yet" (a
// valid startup state) from an actual parse/validation failure.
var ErrEmptyConfigDir = errors.New("no config files found")
