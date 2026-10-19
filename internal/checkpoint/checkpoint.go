package checkpoint

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

const SchemaVersion = 1

type Tool struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type Host struct {
	Hostname  string           `json:"hostname"`
	MachineID string           `json:"machine_id"`
	BootID    string           `json:"boot_id"`
	Kernel    string           `json:"kernel"`
	Addresses []flows.AddrSeen `json:"addresses"`
}

type Run struct {
	RunID                    string            `json:"run_id"`
	StartedAt                time.Time         `json:"started_at"`
	CheckpointAt             time.Time         `json:"checkpoint_at"`
	Generation               uint64            `json:"generation"`
	LastSuccessfulCheckpoint *time.Time        `json:"last_successful_checkpoint,omitempty"`
	Params                   map[string]string `json:"params"`
}

type File struct {
	SchemaVersion int                `json:"schema_version"`
	Kind          string             `json:"kind,omitempty"`
	Tool          Tool               `json:"tool"`
	Host          Host               `json:"host"`
	Run           Run                `json:"run"`
	Coverage      model.Coverage     `json:"coverage"`
	Limits        model.LimitsState  `json:"limits"`
	Dependencies  []model.Dependency `json:"dependencies"`
}

func FileName(hostname, runID string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, hostname)
	return clean + "-" + runID + ".json.gz"
}

func NewRunID() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func Read(path string) (*File, error) {
	var f File
	if err := ReadJSON(path, &f); err != nil {
		return nil, err
	}
	if f.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: unsupported schema_version %d", path, f.SchemaVersion)
	}
	return &f, nil
}

// ReadJSON decodes any gzip-compressed JSON document.
func ReadJSON(path string, v any) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer gz.Close()
	if err := json.NewDecoder(gz).Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
