// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package guard

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// state is the JSON document stored in Config.StateFile.
type state struct {
	Comment   string               `json:"_comment"`
	Whitelist map[string]time.Time `json:"whitelist"`
	Bans      map[string]*record   `json:"ips"`
	Mailboxes map[string]*record   `json:"mailboxes"`
}

const stateComment = "Managed by mailproxy; rewritten every few seconds. Use the access file for manual allow/deny entries."

func (g *Guard) loadState() {
	if g.cfg.StateFile == "" {
		return
	}
	b, err := os.ReadFile(g.cfg.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		g.log.Error("guard: reading state file", "file", g.cfg.StateFile, "err", err)
		return
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		g.log.Error("guard: parsing state file, starting empty", "file", g.cfg.StateFile, "err", err)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range st.Whitelist {
		g.white[k] = v
	}
	for k, v := range st.Bans {
		if v != nil {
			g.ips[k] = v
		}
	}
	for k, v := range st.Mailboxes {
		if v != nil {
			g.mailboxes[k] = v
		}
	}
	g.log.Info("guard: state loaded", "whitelisted", len(g.white), "ips", len(g.ips), "mailboxes", len(g.mailboxes))
}

func (g *Guard) saveState() {
	if g.cfg.StateFile == "" {
		return
	}
	g.mu.Lock()
	if !g.dirty {
		g.mu.Unlock()
		return
	}
	st := state{Comment: stateComment, Whitelist: map[string]time.Time{}, Bans: map[string]*record{}, Mailboxes: map[string]*record{}}
	for k, v := range g.white {
		st.Whitelist[k] = v
	}
	for k, v := range g.ips {
		c := *v
		c.seen = nil
		st.Bans[k] = &c
	}
	for k, v := range g.mailboxes {
		c := *v
		c.seen = nil
		st.Mailboxes[k] = &c
	}
	g.dirty = false
	g.mu.Unlock()

	b, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		err = writeAtomic(g.cfg.StateFile, b)
	}
	if err != nil {
		g.log.Error("guard: writing state file", "file", g.cfg.StateFile, "err", err)
		g.mu.Lock()
		g.dirty = true
		g.mu.Unlock()
	}
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// reloadAccess (re)reads the access file if its content changed.
func (g *Guard) reloadAccess() {
	if g.cfg.AccessFile == "" {
		return
	}
	b, err := os.ReadFile(g.cfg.AccessFile)
	sig := ""
	switch {
	case errors.Is(err, fs.ErrNotExist):
		sig = "missing"
	case err != nil:
		sig = "error: " + err.Error()
	default:
		sig = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	g.mu.Lock()
	unchanged := sig == g.accessSig
	g.accessSig = sig
	g.mu.Unlock()
	if unchanged {
		return
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			g.log.Info("guard: no access file", "file", g.cfg.AccessFile)
		} else {
			g.log.Error("guard: reading access file", "file", g.cfg.AccessFile, "err", err)
		}
		g.mu.Lock()
		g.rules = nil
		g.mu.Unlock()
		return
	}
	rules, warnings := ParseRules(bytes.NewReader(b))
	for _, w := range warnings {
		g.log.Warn("guard: access file", "file", g.cfg.AccessFile, "problem", w)
	}
	g.mu.Lock()
	g.rules = rules
	g.mu.Unlock()
	g.log.Info("guard: access file loaded", "file", g.cfg.AccessFile, "entries", rules.Count())
}
