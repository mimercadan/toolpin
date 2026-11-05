package scan

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Tool is the subset of an MCP tool definition we care about.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Unit is one reviewable thing: a whole text file, or a single MCP tool.
type Unit struct {
	ID   string // stable key, e.g. "tools.json#read_file" or "skills/foo/SKILL.md"
	Path string
	Tool *Tool
	Text string // what the agent will actually read
	Line int    // line offset of Text inside the file (0 for whole files)
}

var textExt = map[string]bool{".md": true, ".mdc": true, ".txt": true, ".yaml": true, ".yml": true, ".toml": true, ".prompt": true}
var specialNames = map[string]bool{".cursorrules": true, ".windsurfrules": true, ".clinerules": true}

func skipDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "dist"
}

// Collect walks the given paths and returns scannable units.
func Collect(paths []string) ([]Unit, error) {
	var units []Unit
	for _, root := range paths {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != root && skipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			key := filepath.Base(p)
			if rel, rerr := filepath.Rel(root, p); rerr == nil && rel != "." {
				key = rel
			}
			u, err := load(p, filepath.ToSlash(key))
			if err != nil {
				return err
			}
			units = append(units, u...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(units, func(i, j int) bool { return units[i].ID < units[j].ID })
	return units, nil
}

// IDs are relative to the scanned root so a lockfile works from any checkout.
func load(p, key string) ([]Unit, error) {
	ext := strings.ToLower(filepath.Ext(p))
	base := filepath.Base(p)
	if ext != ".json" && !textExt[ext] && !specialNames[base] {
		return nil, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if ext == ".json" {
		if tools := parseTools(data); tools != nil {
			var out []Unit
			src := string(data)
			for i := range tools {
				t := tools[i]
				text := t.Description
				if len(t.InputSchema) > 0 {
					text += "\n" + strings.Join(schemaStrings(t.InputSchema), "\n")
				}
				out = append(out, Unit{ID: key + "#" + t.Name, Path: p, Tool: &t, Text: text, Line: lineOf(src, `"`+t.Name+`"`)})
			}
			return out, nil
		}
		return nil, nil // non-tool JSON is ignored
	}
	return []Unit{{ID: key, Path: p, Text: string(data)}}, nil
}

// parseTools accepts the common shapes of an MCP tools/list dump:
// {"tools":[...]}, {"result":{"tools":[...]}}, or a bare [...] array.
func parseTools(data []byte) []Tool {
	var a struct {
		Tools  []Tool `json:"tools"`
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &a) == nil {
		if len(a.Tools) > 0 {
			return a.Tools
		}
		if len(a.Result.Tools) > 0 {
			return a.Result.Tools
		}
	}
	var arr []Tool
	if json.Unmarshal(data, &arr) == nil && len(arr) > 0 && arr[0].Name != "" {
		return arr
	}
	return nil
}

// schemaStrings pulls every string (param descriptions, enums, defaults)
// out of a JSON schema, since poisoning often hides in parameter docs.
func schemaStrings(raw json.RawMessage) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

func lineOf(src, needle string) int {
	i := strings.Index(src, needle)
	if i < 0 {
		return 0
	}
	return strings.Count(src[:i], "\n")
}

// ScanUnit scans one unit.
func ScanUnit(u Unit) []Finding {
	src := u.ID
	return Text(src, u.Text, u.Line)
}
