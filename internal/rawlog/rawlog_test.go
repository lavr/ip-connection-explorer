package rawlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRawRotatesAndCaps(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, "r1", 1024, 3*1024)
	if err != nil {
		t.Fatal(err)
	}
	rec := map[string]any{"at": time.Unix(1, 0).UTC(), "pad": strings.Repeat("x", 90)}
	for i := 0; i < 100; i++ {
		if err := w.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "raw-r1-*.jsonl.gz"))
	if len(files) == 0 || len(files) > 4 {
		t.Fatalf("files=%v", files)
	}
	b, err := os.ReadFile(filepath.Join(dir, "raw-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var side struct {
		RetainedFrom string   `json:"retained_from"`
		Files        []string `json:"files"`
		Dropped      int      `json:"dropped_files"`
	}
	if err := json.Unmarshal(b, &side); err != nil || side.RetainedFrom == "" || side.Dropped == 0 || len(side.Files) != len(files) {
		t.Fatalf("%s %v", b, err)
	}
}
