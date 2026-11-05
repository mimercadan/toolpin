// Package scan detects prompt-injection and tool-poisoning patterns in
// text that AI agents will read: MCP tool descriptions, SKILL.md files,
// agent rules (AGENTS.md, .cursorrules) and similar.
package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	}
	return "?"
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converts "low|medium|high|critical" to a Severity.
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(v) {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	case "critical":
		return Critical, nil
	}
	return 0, fmt.Errorf("unknown severity %q", v)
}

// Finding is one suspicious match.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Source   string   `json:"source"`  // file path (and tool name if any)
	Line     int      `json:"line"`    // 1-based
	Snippet  string   `json:"snippet"` // visible excerpt
}

type regexRule struct {
	id  string
	sev Severity
	msg string
	re  *regexp.Regexp
}

var regexRules = []regexRule{
	{"override-instructions", Critical, "Tries to override the agent's prior/system instructions",
		regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|system|original)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|guidelines|directives)`)},
	{"conceal-from-user", Critical, "Asks the agent to hide actions from the user",
		regexp.MustCompile(`(?i)\b(do not|don't|never|without)\b[^.\n]{0,25}\b(tell|inform|mention|notify|alert|show|reveal|tell)(ing)?\b[^.\n]{0,15}\b(the )?(user|human|operator)`)},
	{"secret-paths", High, "References credential files or secret stores",
		regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|\.npmrc|\.pypirc|\.netrc|\.docker/config\.json|\.kube/config|keychain|wallet\.dat|mcp\.json|claude_desktop_config)`)},
	{"pipe-to-shell", High, "Downloads and executes remote code",
		regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(ba|z)?sh\b|\b(curl|wget)\b[^\n]{0,200}\|\s*(python3?|node|iex)\b`)},
	{"exfil-instruction", High, "Instructs the agent to send data to an external endpoint",
		regexp.MustCompile(`(?i)\b(send|post|upload|forward|transmit|exfiltrate|append)\b[^.\n]{0,60}\b(to|into)\b[^.\n]{0,20}(https?://|webhook|endpoint|server|discord\.com/api/webhooks|pastebin)`)},
	{"templated-url", Medium, "URL with placeholders that could smuggle data out (e.g. ?q={secret})",
		regexp.MustCompile(`(?i)https?://[^\s"'<>]+[?&][a-z0-9_]+=(\{\{?[^}]+\}?\}|\$\{?[a-z_]+\}?|<[a-z_ ]+>)`)},
	{"tool-shadowing", High, "Description tries to change how OTHER tools behave",
		regexp.MustCompile(`(?i)\b(when|whenever|before|after)\b[^.\n]{0,40}\b(using|calling|invoking|running)\b[^.\n]{0,30}\b(tool|function|command)s?\b[^.\n]{0,60}\b(always|must|also|instead)\b`)},
	{"role-hijack", Medium, "Fake role/system markers that may confuse the model",
		regexp.MustCompile(`(?i)(<\|?\s*(system|im_start|im_end)\s*\|?>|\[/?(system|inst)\]|^\s*(system|assistant)\s*:|<\s*important\s*>|<\s*system[-_ ]?(prompt|message)?\s*>)`)},
	{"priority-pressure", Low, "Urgency language often used in poisoning payloads",
		regexp.MustCompile(`(?i)\b(this is (very |extremely )?(important|critical|mandatory)|you must comply|failure to (do so|comply)|highest priority|required by the system)\b`)},
}

var (
	base64Blob  = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
	htmlComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	instrWords  = regexp.MustCompile(`(?i)\b(you|agent|assistant|model|must|always|never|ignore|send|read|execute|run)\b`)
)

// invisibleKind classifies characters a human reviewer can't see.
func invisibleKind(r rune) string {
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		return "unicode tag character (ASCII smuggling)"
	case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF || r == 0x180E:
		return "zero-width character"
	case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
		return "bidirectional override"
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return "variation selector"
	}
	return ""
}

// DecodeTags reveals text hidden with Unicode tag characters.
func DecodeTags(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0xE0020 && r <= 0xE007E {
			b.WriteRune(r - 0xE0000)
		}
	}
	return b.String()
}

func visible(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if invisibleKind(r) != "" {
			continue
		}
		if r == '\n' || r == '\t' {
			r = ' '
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(out) > max {
		rs := []rune(out)
		out = string(rs[:max]) + "…"
	}
	return out
}

// Text scans a block of text. lineOffset lets callers map embedded text
// (e.g. a JSON field) back to a line in the original file.
func Text(source, text string, lineOffset int) []Finding {
	var out []Finding
	lines := strings.Split(text, "\n")

	for i, line := range lines {
		ln := i + 1 + lineOffset

		// Invisible characters (report one finding per kind per line).
		seen := map[string]int{}
		for _, r := range line {
			if k := invisibleKind(r); k != "" {
				seen[k]++
			}
		}
		kinds := make([]string, 0, len(seen))
		for k := range seen {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			sev := High
			msg := fmt.Sprintf("%d hidden %s(s) a human reviewer cannot see", seen[k], k)
			if strings.HasPrefix(k, "unicode tag") {
				sev = Critical
				if hidden := DecodeTags(line); hidden != "" {
					msg += fmt.Sprintf(" — decoded: %q", visible(hidden, 120))
				}
			}
			out = append(out, Finding{"invisible-unicode", sev, msg, source, ln, visible(line, 80)})
		}

		// Regex rules run on the visible text so that zero-width tricks
		// ("ig​nore") don't evade them.
		clean := visible(line, 1<<20)
		for _, rr := range regexRules {
			if m := rr.re.FindString(clean); m != "" {
				out = append(out, Finding{rr.id, rr.sev, rr.msg, source, ln, visible(m, 80)})
			}
		}
		if m := base64Blob.FindString(line); m != "" {
			out = append(out, Finding{"encoded-blob", Medium, "Long base64-like blob; payloads are often hidden this way", source, ln, m[:40] + "…"})
		}
	}

	// Tag-smuggled text can also carry regex-rule payloads.
	if hidden := DecodeTags(text); hidden != "" {
		for _, rr := range regexRules {
			if m := rr.re.FindString(hidden); m != "" {
				out = append(out, Finding{rr.id + "(hidden)", Critical, rr.msg + " — inside invisible text", source, lineOffset + 1, visible(m, 80)})
			}
		}
	}

	// HTML comments are invisible in rendered Markdown but read by agents.
	for _, m := range htmlComment.FindAllStringSubmatchIndex(text, -1) {
		body := text[m[2]:m[3]]
		if len(instrWords.FindAllString(body, -1)) >= 2 {
			ln := strings.Count(text[:m[0]], "\n") + 1 + lineOffset
			out = append(out, Finding{"hidden-comment", High, "HTML comment with instructions (invisible when rendered)", source, ln, visible(body, 80)})
		}
	}
	return out
}

// Score turns findings into a 0-100 risk score.
func Score(fs []Finding) int {
	pts := 0
	for _, f := range fs {
		pts += []int{0, 3, 10, 25, 40}[f.Severity]
	}
	if pts > 100 {
		pts = 100
	}
	return pts
}
