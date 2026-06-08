// Package runtime holds the immutable, pre-compiled runtime snapshot behind an atomic pointer, providing lock-free reads on the hot path and atomic swaps on reload.
package runtime
