package checkpoint

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// ErrStale is returned when a newer generation of the same checkpoint was already written.
var ErrStale = errors.New("checkpoint generation is older than the one on disk")

// fence remembers the newest generation committed per checkpoint path in this process, so a
// slow writer can never replace a newer checkpoint with an older one.
var fence = struct {
	sync.Mutex
	gen map[string]uint64
}{gen: map[string]uint64{}}

type writerFS interface {
	CreateTemp(dir, pattern string) (*os.File, error)
	Sync(*os.File) error
	Rename(oldpath, newpath string) error
	Remove(name string) error
}

type osFS struct{}

func (osFS) CreateTemp(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }
func (osFS) Sync(f *os.File) error                            { return f.Sync() }
func (osFS) Rename(o, n string) error                         { return os.Rename(o, n) }
func (osFS) Remove(name string) error                         { return os.Remove(name) }

var fsys writerFS = osFS{}

func Write(dir string, f *File) (string, error) {
	path := filepath.Join(dir, FileName(f.Host.Hostname, f.Run.RunID))
	gen := f.Run.Generation
	return path, write(path, f, func() error {
		if last, ok := fence.gen[path]; ok && gen <= last {
			return ErrStale
		}
		fence.gen[path] = gen
		return nil
	})
}

// WriteTo replaces path atomically: on any error the previous file is left untouched.
func WriteTo(path string, v any) error {
	return write(path, v, nil)
}

// write encodes v to a temporary file and renames it over path. admit, if set, is checked
// under the fence lock right before the rename.
func write(path string, v any, admit func() error) (err error) {
	tmp, err := fsys.CreateTemp(filepath.Dir(path), ".ipcx-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = fsys.Remove(tmp.Name())
		}
	}()
	gz := gzip.NewWriter(tmp)
	if err = json.NewEncoder(gz).Encode(v); err != nil {
		return err
	}
	if err = gz.Close(); err != nil {
		return err
	}
	if err = fsys.Sync(tmp); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if admit != nil {
		fence.Lock()
		defer fence.Unlock()
		if err = admit(); err != nil {
			return err
		}
	}
	if err = fsys.Rename(tmp.Name(), path); err != nil {
		return errors.Join(err, fsys.Remove(tmp.Name()))
	}
	return nil
}
