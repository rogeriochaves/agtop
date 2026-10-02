package secrets

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Detected is one secret Find found in a message.
type Detected struct {
	// Value is the secret itself, Start and End its byte span in the text.
	Value      string
	Start, End int
	// Kind is the rule that found it (provider_api_key, github_token, ...).
	Kind string
	// SuggestedName is the vault name to offer: the name it is assigned to
	// in the text, else a default for its kind.
	SuggestedName string
}

// Find returns the secrets in a message someone is about to send, skipping
// examples and placeholders (sk-proj-xxxx..., AKIA...EXAMPLE, your-key-here).
// Text past the scan budget is scanned in slices.
func Find(text string) []Detected {
	var out []Detected
	offset := 0
	for _, s := range sliceForScan(text) {
		for _, m := range detectSlice(s, Options{}) {
			v := s[m.SecretStart:m.SecretEnd]
			if v == "" || isPlaceholderSecret(v) {
				continue
			}
			d := Detected{Value: v, Start: offset + m.SecretStart, End: offset + m.SecretEnd, Kind: m.RuleID}
			d.SuggestedName = suggestName(text, d, offset+m.Start)
			out = append(out, d)
		}
		offset += len(s)
	}
	return out
}

// placeholderWords mark a value as an example rather than a credential.
var placeholderWords = []string{"xxxx", "****", "....", "<", ">", "{{", "your", "example",
	"placeholder", "changeme", "redacted", "dummy", "sample", "insert", "replace"}

// isPlaceholderSecret is a value shaped like a key that is really an
// example: a placeholder word in it, or too repetitive to be random.
func isPlaceholderSecret(v string) bool {
	l := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return len(v) >= 16 && shannonEntropy(v) < 3.0
}

var (
	envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// assignedTo reads the name a value is assigned to, right before it:
	// NAME=, export NAME=, NAME: and "NAME": ", with the value's opening
	// quote. The name must start the text or follow a space or a
	// delimiter, so user:password in a URL names nothing.
	assignedTo = regexp.MustCompile(`(?:^|[\s"'{,(;\[])["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*["'` + "`" + `]?$`)
)

var defaultNames = map[string]string{
	"github_token":      "GITHUB_TOKEN",
	"aws_access_key_id": "AWS_ACCESS_KEY_ID",
	"slack_token":       "SLACK_TOKEN",
	"stripe_secret_key": "STRIPE_SECRET_KEY",
}

// suggestName is the name d's value is assigned to in text (looked for
// right before the secret, then before the whole credential, for a URL),
// uppercased, else a default for its kind.
func suggestName(text string, d Detected, credentialStart int) string {
	for _, at := range []int{d.Start, credentialStart} {
		if m := assignedTo.FindStringSubmatch(text[:at]); m != nil && envName.MatchString(m[1]) {
			return strings.ToUpper(m[1])
		}
	}
	if d.Kind == "provider_api_key" {
		if strings.HasPrefix(d.Value, "sk-ant-") {
			return "ANTHROPIC_API_KEY"
		}
		return "OPENAI_API_KEY"
	}
	if n := defaultNames[d.Kind]; n != "" {
		return n
	}
	return "SECRET"
}

// UniqueName is base, or base_2, base_3... the first that is not taken.
func UniqueName(base string, existing []string) string {
	if !slices.Contains(existing, base) {
		return base
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s_%d", base, i); !slices.Contains(existing, n) {
			return n
		}
	}
}

// Ref is how a message names a vault secret in place of its value.
func Ref(name string) string { return "{{vault:" + name + "}}" }

// Note is what Replace appends, once, to tell the agent how to use it.
func Note(name string) string {
	return "\n\n(" + Ref(name) + " is a Kanban vault secret. Use it with `kv run " + name + " -- <cmd>`, never print it.)"
}

// Replace puts {{vault:NAME}} in place of every occurrence of value and
// appends the note on using it, once.
func Replace(text, value, name string) string {
	if value != "" {
		text = strings.ReplaceAll(text, value, Ref(name))
	}
	if !strings.Contains(text, Note(name)) {
		text += Note(name)
	}
	return text
}
