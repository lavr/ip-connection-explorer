package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestReportCommand(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"ipcx", "report", "../../testdata/a.json.gz", "--format", "csv"}, &out, io.Discard); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.HasPrefix(out.String(), "role_status,") || strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("%q", out.String())
	}
}

func TestReportUsage(t *testing.T) {
	if code := run([]string{"ipcx", "report"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if code := run([]string{"ipcx", "report", "../../testdata/a.json.gz", "--format", "xml"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
}
