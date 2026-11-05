// toolpin: a linter + lockfile for the text your AI agents trust.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mimercadan/toolpin/internal/pin"
	"github.com/mimercadan/toolpin/internal/scan"
)

const version = "0.1.0"

const usage = `toolpin %s — lint and pin the text your AI agents trust

Usage:
  toolpin scan   [--json] [--fail-on high] <path>...   find prompt-injection / tool-poisoning
  toolpin pin    [--lock toolpin.lock] <path>...       record hashes of every tool & skill
  toolpin verify [--lock toolpin.lock] <path>...       fail if anything changed since pin (rug pull)
  toolpin reveal <file>                                print text hidden in Unicode tag chars

Paths can be MCP tools/list JSON dumps, SKILL.md files, AGENTS.md,
.cursorrules, or whole directories.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "scan":
		code = runScan(args)
	case "pin":
		code = runPin(args)
	case "verify":
		code = runVerify(args)
	case "reveal":
		code = runReveal(args)
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Printf(usage, version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, version)
		code = 2
	}
	os.Exit(code)
}

var useColor = os.Getenv("NO_COLOR") == "" && isTTY()

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func color(c, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + c + "m" + s + "\033[0m"
}

func sevColor(s scan.Severity) string {
	switch s {
	case scan.Critical:
		return color("1;35", s.String())
	case scan.High:
		return color("1;31", s.String())
	case scan.Medium:
		return color("33", s.String())
	}
	return color("36", s.String())
}

func collect(fsFlags *flag.FlagSet) []scan.Unit {
	paths := fsFlags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	units, err := scan.Collect(paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	return units
}

func runScan(args []string) int {
	f := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := f.Bool("json", false, "machine-readable output")
	failOn := f.String("fail-on", "high", "exit 1 if any finding is at or above this severity (low|medium|high|critical)")
	f.Parse(args)
	threshold, err := scan.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	units := collect(f)

	var all []scan.Finding
	for _, u := range units {
		all = append(all, scan.ScanUnit(u)...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Severity != all[j].Severity {
			return all[i].Severity > all[j].Severity
		}
		return all[i].Source < all[j].Source
	})
	failed := false
	for _, x := range all {
		if x.Severity >= threshold {
			failed = true
		}
	}

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"units": len(units), "score": scan.Score(all), "findings": all,
		})
	} else {
		printReport(units, all)
	}
	if failed {
		return 1
	}
	return 0
}

func printReport(units []scan.Unit, all []scan.Finding) {
	tools := 0
	for _, u := range units {
		if u.Tool != nil {
			tools++
		}
	}
	fmt.Printf("%s scanned %d files/tools (%d MCP tools)\n\n", color("1", "toolpin"), len(units), tools)
	if len(all) == 0 {
		fmt.Println(color("32", "✔ no injection patterns found"))
		return
	}
	bySrc := map[string][]scan.Finding{}
	var order []string
	for _, x := range all {
		if _, ok := bySrc[x.Source]; !ok {
			order = append(order, x.Source)
		}
		bySrc[x.Source] = append(bySrc[x.Source], x)
	}
	for _, src := range order {
		fs := bySrc[src]
		fmt.Printf("%s  %s\n", color("1", src), color("2", fmt.Sprintf("risk %d/100", scan.Score(fs))))
		for _, x := range fs {
			fmt.Printf("  %-17s L%-4d %-26s %s\n", sevColor(x.Severity), x.Line, x.Rule, x.Message)
			if x.Snippet != "" {
				fmt.Printf("  %s %s\n", strings.Repeat(" ", 31), color("2", "› "+x.Snippet))
			}
		}
		fmt.Println()
	}
	counts := map[scan.Severity]int{}
	for _, x := range all {
		counts[x.Severity]++
	}
	fmt.Printf("%d findings — %d critical, %d high, %d medium, %d low · overall risk %d/100\n",
		len(all), counts[scan.Critical], counts[scan.High], counts[scan.Medium], counts[scan.Low], scan.Score(all))
}

func runPin(args []string) int {
	f := flag.NewFlagSet("pin", flag.ExitOnError)
	lock := f.String("lock", "toolpin.lock", "lockfile path")
	f.Parse(args)
	units := collect(f)
	if err := pin.Write(*lock, pin.Build(units)); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Printf("📌 pinned %d entries to %s\n", len(units), *lock)
	return 0
}

func runVerify(args []string) int {
	f := flag.NewFlagSet("verify", flag.ExitOnError)
	lock := f.String("lock", "toolpin.lock", "lockfile path")
	f.Parse(args)
	l, err := pin.Read(*lock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading lock (run `toolpin pin` first):", err)
		return 2
	}
	units := collect(f)
	d := pin.Compare(l, units)
	if d.Clean() {
		fmt.Printf("%s all %d entries match %s\n", color("32", "✔"), len(units), *lock)
		return 0
	}
	byID := map[string]scan.Unit{}
	for _, u := range units {
		byID[u.ID] = u
	}
	for _, id := range d.Changed {
		fmt.Printf("%s %s  (content changed since it was pinned)\n", color("1;31", "CHANGED"), id)
		for _, x := range scan.ScanUnit(byID[id]) {
			fmt.Printf("        ↳ %s %s: %s\n", sevColor(x.Severity), x.Rule, x.Message)
		}
	}
	for _, id := range d.Added {
		fmt.Printf("%s   %s\n", color("33", "ADDED"), id)
	}
	for _, id := range d.Removed {
		fmt.Printf("%s %s\n", color("36", "REMOVED"), id)
	}
	fmt.Printf("\n✖ %d changed, %d added, %d removed — review, then re-run `toolpin pin` to accept\n",
		len(d.Changed), len(d.Added), len(d.Removed))
	return 1
}

func runReveal(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: toolpin reveal <file>")
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	h := scan.DecodeTags(string(b))
	if h == "" {
		fmt.Println("no tag-encoded hidden text found")
		return 0
	}
	fmt.Println(h)
	return 1
}
