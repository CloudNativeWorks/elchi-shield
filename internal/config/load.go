package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ReadDir reads and parses every recognized config file in dir. Files are
// returned in sorted-name order. Parse errors for individual files are
// aggregated; a non-nil error means at least one file failed to parse. If the
// directory contains no config files, it returns ErrEmptyConfigDir.
func ReadDir(dir string) ([]ParsedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// A MISSING config dir is "no config", not a hard reload failure. The
			// agent's atomic reconcile (elchi-client) removes-then-recreates the
			// watched dir, so a reload fired mid-window briefly sees it absent; the
			// watcher itself already waits for the dir to (re)appear. Treat it like
			// an empty dir — keep last-good, WARN, and do NOT advance the
			// reload-failure counter (which upstream misreads as a config rejection).
			return nil, ErrEmptyConfigDir
		}
		return nil, fmt.Errorf("read config dir %q: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !isConfigFile(e.Name()) {
			continue
		}
		names = append(names, filepath.Join(dir, e.Name()))
	}
	sort.Strings(names)

	if len(names) == 0 {
		return nil, ErrEmptyConfigDir
	}

	var merr MultiError
	parsed := make([]ParsedFile, 0, len(names))
	for _, name := range names {
		data, rerr := os.ReadFile(name)
		if rerr != nil {
			merr.Add(newFileError(name, "", fmt.Errorf("read: %w", rerr)))
			continue
		}
		f, perr := Parse(name, data)
		if perr != nil {
			merr.Add(perr)
			continue
		}
		parsed = append(parsed, ParsedFile{Name: name, File: f})
	}

	if err := merr.ErrorOrNil(); err != nil {
		return parsed, err
	}
	return parsed, nil
}

// Load reads, parses, validates (per-file and cross-file), and merges every
// config file in dir into a validated *MergedConfig. On any problem it returns
// a nil config and an aggregated error describing every issue, so the caller
// can keep its last-good snapshot active. ErrEmptyConfigDir is returned (as the
// error) when the directory has no config files.
func Load(dir string) (*MergedConfig, error) {
	parsed, err := ReadDir(dir)
	if err != nil {
		// Parse/read failures (and ErrEmptyConfigDir) propagate as-is.
		return nil, err
	}

	var merr MultiError
	for _, pf := range parsed {
		for _, e := range validateFile(pf.Name, pf.File) {
			merr.Add(e)
		}
	}

	merged := Merge(parsed)
	for _, e := range validateMerged(merged) {
		merr.Add(e)
	}

	if err := merr.ErrorOrNil(); err != nil {
		return nil, err
	}
	return merged, nil
}
