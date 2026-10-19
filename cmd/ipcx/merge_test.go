package main

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
)

func TestMergeNoInputs(t *testing.T) {
	if code := run([]string{"ipcx", "merge", "-o", filepath.Join(t.TempDir(), "x.json.gz")}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestMergeMissingOutput(t *testing.T) {
	if code := run([]string{"ipcx", "merge", "../../testdata/a.json.gz"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestMergeFixtures(t *testing.T) {
	out := filepath.Join(t.TempDir(), "m.json.gz")
	if code := run([]string{"ipcx", "merge", "../../testdata/a.json.gz", "../../testdata/b.json.gz", "-o", out}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code=%d", code)
	}
	var m struct {
		Kind         string `json:"kind"`
		Dependencies []any  `json:"dependencies"`
	}
	if err := checkpoint.ReadJSON(out, &m); err != nil || m.Kind != "merged" || len(m.Dependencies) != 2 {
		t.Fatalf("%v %+v", err, m)
	}
}

func TestMergeBadInput(t *testing.T) {
	if code := run([]string{"ipcx", "merge", "missing.json.gz", "-o", filepath.Join(t.TempDir(), "x")}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("code=%d", code)
	}
}
