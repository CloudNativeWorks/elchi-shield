package config

import "sort"

// ParsedFile pairs a parsed File with the path it came from, so downstream
// merge/validate steps can attribute problems to a source.
type ParsedFile struct {
	Name string
	File *File
}

// MergedDomain is a Domain annotated with the file it originated from.
type MergedDomain struct {
	Domain
	Source string
}

// MergedConfig is the deterministic combination of every config file in the
// directory. It is pure data: parsing/merging is done, but compilation into the
// hot-path form happens later (in the policy package).
type MergedConfig struct {
	// FileDefaults is the field-by-field overlay of every file's `defaults`
	// block, applied beneath domain and route policies during resolution.
	FileDefaults PolicySpec
	// Domains is every domain across all files, in deterministic order.
	Domains []MergedDomain
	// Sources lists the contributing files in sorted order.
	Sources []string
}

// Merge folds parsed files into a single MergedConfig. Files are processed in
// sorted-name order so the result is deterministic and "later file wins" for
// overlapping scalar defaults. Domains are concatenated (collision detection is
// a validation concern, not a merge concern).
func Merge(files []ParsedFile) *MergedConfig {
	sorted := make([]ParsedFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	out := &MergedConfig{}
	for _, pf := range sorted {
		if pf.File == nil {
			continue
		}
		out.Sources = append(out.Sources, pf.Name)
		out.FileDefaults = overlaySpec(out.FileDefaults, pf.File.Spec.Defaults)
		for _, d := range pf.File.Spec.Domains {
			out.Domains = append(out.Domains, MergedDomain{Domain: d, Source: pf.Name})
		}
	}
	return out
}

// overlaySpec returns base with every field that is set in over taking
// precedence. SkipChecks unions; Checks sub-blocks replace when set.
func overlaySpec(base, over PolicySpec) PolicySpec {
	out := base
	if over.Mode != nil {
		out.Mode = over.Mode
	}
	if over.FailMode != nil {
		out.FailMode = over.FailMode
	}
	if over.InspectRequestBody != nil {
		out.InspectRequestBody = over.InspectRequestBody
	}
	if over.InspectResponseBody != nil {
		out.InspectResponseBody = over.InspectResponseBody
	}
	if over.MaxRequestBodyBytes != nil {
		out.MaxRequestBodyBytes = over.MaxRequestBodyBytes
	}
	if over.MaxResponseBodyBytes != nil {
		out.MaxResponseBodyBytes = over.MaxResponseBodyBytes
	}
	if over.MaxHeaderBytes != nil {
		out.MaxHeaderBytes = over.MaxHeaderBytes
	}
	if over.Timeout != nil {
		out.Timeout = over.Timeout
	}
	if over.LogLevel != nil {
		out.LogLevel = over.LogLevel
	}
	if over.SamplingRate != nil {
		out.SamplingRate = over.SamplingRate
	}
	if len(over.SkipChecks) > 0 {
		out.SkipChecks = unionStrings(out.SkipChecks, over.SkipChecks)
	}
	if over.Pipeline != nil {
		out.Pipeline = over.Pipeline
	}
	if over.Checks.Headers != nil {
		out.Checks.Headers = over.Checks.Headers
	}
	if over.Checks.Body != nil {
		out.Checks.Body = over.Checks.Body
	}
	if over.Engines != nil {
		out.Engines = over.Engines
	}
	return out
}

// unionStrings returns the de-duplicated union of a and b, preserving a's order
// then appending new entries from b.
func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
