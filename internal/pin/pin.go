// Package pin implements a lockfile for agent-facing text, so a tool
// description that silently changes after you approved it (an MCP
// "rug pull") is caught in CI.
package pin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/mimercadan/toolpin/internal/scan"
)

type Lock struct {
	Version int               `json:"version"`
	Created string            `json:"created"`
	Entries map[string]string `json:"entries"` // unit ID -> sha256
}

func Hash(u scan.Unit) string {
	h := sha256.New()
	if u.Tool != nil {
		h.Write([]byte(u.Tool.Name + "\x00" + u.Tool.Description + "\x00"))
		h.Write(canonical(u.Tool.InputSchema))
	} else {
		h.Write([]byte(u.Text))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Build(units []scan.Unit) Lock {
	l := Lock{Version: 1, Created: time.Now().UTC().Format(time.RFC3339), Entries: map[string]string{}}
	for _, u := range units {
		l.Entries[u.ID] = Hash(u)
	}
	return l
}

func Write(path string, l Lock) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func Read(path string) (Lock, error) {
	var l Lock
	b, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	err = json.Unmarshal(b, &l)
	return l, err
}

type Diff struct {
	Added, Removed, Changed []string
}

func (d Diff) Clean() bool { return len(d.Added)+len(d.Removed)+len(d.Changed) == 0 }

func Compare(l Lock, units []scan.Unit) Diff {
	var d Diff
	now := map[string]bool{}
	for _, u := range units {
		now[u.ID] = true
		old, ok := l.Entries[u.ID]
		switch {
		case !ok:
			d.Added = append(d.Added, u.ID)
		case old != Hash(u):
			d.Changed = append(d.Changed, u.ID)
		}
	}
	for id := range l.Entries {
		if !now[id] {
			d.Removed = append(d.Removed, id)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	return d
}

// canonical re-encodes JSON with sorted keys and no whitespace so that
// formatting changes in a tools/list dump don't count as a change.
func canonical(raw json.RawMessage) []byte {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return raw
	}
	b, _ := json.Marshal(v)
	return b
}
