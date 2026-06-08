package main

import (
	"strings"
	"testing"
)

func TestIsLoopbackTCP(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:9000":    true,
		"127.0.0.5:9000":    true,
		"[::1]:9000":        true,
		"localhost:9000":    true,
		"0.0.0.0:9000":      false,
		":9000":             false,
		"192.168.1.10:9000": false,
		"example.com:9000":  false,
	}
	for addr, want := range cases {
		if got := isLoopbackTCP(addr); got != want {
			t.Errorf("isLoopbackTCP(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestListenersRejectNonLoopbackTCP(t *testing.T) {
	cfg := appConfig{extprocListeners: stringList{"lst=tcp:0.0.0.0:9000"}}
	if _, err := cfg.listeners(); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("non-loopback tcp listener should be rejected, got %v", err)
	}

	// Loopback is accepted.
	cfg2 := appConfig{extprocListeners: stringList{"lst=tcp:127.0.0.1:9000"}}
	if _, err := cfg2.listeners(); err != nil {
		t.Fatalf("loopback tcp listener should be accepted: %v", err)
	}

	// UDS is always accepted (local by nature).
	cfg3 := appConfig{extprocListeners: stringList{"lst=unix:/run/x.sock"}}
	if _, err := cfg3.listeners(); err != nil {
		t.Fatalf("unix listener should be accepted: %v", err)
	}

	// Escape hatch.
	cfg4 := appConfig{allowNonLoopback: true, extprocListeners: stringList{"lst=tcp:0.0.0.0:9000"}}
	if _, err := cfg4.listeners(); err != nil {
		t.Fatalf("--allow-non-loopback should permit non-loopback: %v", err)
	}
}
