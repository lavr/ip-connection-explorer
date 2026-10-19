package rawlog

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Writer appends JSON lines to rotated gzip files. Sizes are counted before compression;
// the oldest files are deleted once the total exceeds the cap.
type Writer struct {
	mu       sync.Mutex
	dir      string
	runID    string
	fileMax  int64
	totalMax int64

	seq      int
	cur      *os.File
	gz       *gzip.Writer
	curSize  int64
	files    []rawFile
	dropped  int
	retained time.Time
}

type rawFile struct {
	name  string
	size  int64
	first time.Time
}

func Open(dir, runID string, fileMax, totalMax int64) (*Writer, error) {
	w := &Writer{dir: dir, runID: runID, fileMax: fileMax, totalMax: totalMax}
	if err := w.rotate(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) Write(rec any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if w.curSize > 0 && w.curSize+int64(len(b)) > w.fileMax {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	if _, err := w.gz.Write(b); err != nil {
		return err
	}
	w.curSize += int64(len(b))
	w.files[len(w.files)-1].size = w.curSize
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.closeCurrent()
	if serr := w.writeSidecar(); err == nil {
		err = serr
	}
	return err
}

func (w *Writer) closeCurrent() error {
	if w.cur == nil {
		return nil
	}
	err := w.gz.Close()
	if cerr := w.cur.Close(); err == nil {
		err = cerr
	}
	w.cur, w.gz = nil, nil
	return err
}

func (w *Writer) rotate() error {
	if err := w.closeCurrent(); err != nil {
		return err
	}
	w.seq++
	name := fmt.Sprintf("raw-%s-%04d.jsonl.gz", w.runID, w.seq)
	f, err := os.OpenFile(filepath.Join(w.dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w.cur, w.gz, w.curSize = f, gzip.NewWriter(f), 0
	w.files = append(w.files, rawFile{name: name, first: time.Now().UTC()})
	w.enforceTotal()
	return w.writeSidecar()
}

func (w *Writer) enforceTotal() {
	var total int64
	for _, f := range w.files {
		total += f.size
	}
	for len(w.files) > 1 && total > w.totalMax {
		old := w.files[0]
		_ = os.Remove(filepath.Join(w.dir, old.name))
		total -= old.size
		w.files = w.files[1:]
		w.dropped++
	}
	w.retained = w.files[0].first
}

func (w *Writer) writeSidecar() error {
	side := struct {
		RunID        string    `json:"run_id"`
		RetainedFrom time.Time `json:"retained_from"`
		Files        []string  `json:"files"`
		Dropped      int       `json:"dropped_files"`
	}{RunID: w.runID, RetainedFrom: w.retained, Dropped: w.dropped}
	for _, f := range w.files {
		side.Files = append(side.Files, f.name)
	}
	b, err := json.MarshalIndent(side, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(w.dir, ".raw-"+w.runID+".json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(w.dir, "raw-"+w.runID+".json"))
}
