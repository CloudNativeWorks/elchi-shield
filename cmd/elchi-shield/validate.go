package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// runValidate implements the `elchi-shield validate <dir>` subcommand. It runs the
// config parse → validate → merge pipeline against dir and reports every problem
// with file + field attribution (FileError/MultiError), touching no running state.
//
// elchi-client invokes it on a STAGED config bundle — against the real shield
// binary on the same host, so the same version that will run the config is the one
// that judges it — BEFORE committing the bundle live. A bad config is thus rejected
// with a precise, actionable error (e.g. "api.yaml: domains[2].routes[0].match.
// path_regex: invalid regex") that flows back to the control plane, instead of
// landing on disk and being silently rejected at reload (kept last-good).
//
// Scope: parse + schema/field validation (the bulk of misconfiguration, and the
// part that is directory-self-contained). Engine COMPILE (Coraza ruleset build,
// data-file loading) is intentionally not run here — it depends on referenced data
// files and their resolution, and any compile-stage failure is still caught at the
// real reload. Exit codes: 0 = valid (an empty dir is valid — it means "clear");
// 1 = invalid (errors printed to stderr); 2 = usage error.
func runValidate(args []string) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(os.Stderr, "usage: elchi-shield validate <config-dir>")
		return 2
	}
	if _, err := config.Load(args[0]); err != nil {
		if errors.Is(err, config.ErrEmptyConfigDir) {
			// An empty directory is a valid "no config / clear" state (matches the
			// reloader, which keeps protection rather than failing on an empty dir).
			fmt.Println("ok: empty config directory (nothing to validate)")
			return 0
		}
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	fmt.Println("ok: config valid")
	return 0
}
