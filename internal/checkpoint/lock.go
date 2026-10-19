package checkpoint

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrLocked = errors.New("state directory is locked")

func Lock(dir string) (func() error, error) {
	fh, err := os.OpenFile(filepath.Join(dir, ".ipcx.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(fh.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		fh.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() error {
		err := unix.Flock(int(fh.Fd()), unix.LOCK_UN)
		return errors.Join(err, fh.Close())
	}, nil
}
