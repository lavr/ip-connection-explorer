package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"ipcx", "--version"}, &out, io.Discard)
	if code != 0 || !strings.HasPrefix(out.String(), "ipcx dev (none)") {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
}

func TestUnknownSubcommand(t *testing.T) {
	if code := run([]string{"ipcx", "nope"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestNoArgs(t *testing.T) {
	if code := run([]string{"ipcx"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
}
