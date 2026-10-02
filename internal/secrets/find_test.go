package secrets

import (
	"strings"
	"testing"
)

func TestFindNamesTheSecret(t *testing.T) {
	proj := "sk-proj-" + b(40)
	ant := "sk-ant-api03-" + b(40)
	gh := "ghp_" + b(36)
	cases := []struct{ label, text, value, kind, name string }{
		{"an OpenAI key alone", "use " + proj + " for this", proj, "provider_api_key", "OPENAI_API_KEY"},
		{"an Anthropic key", ant, ant, "provider_api_key", "ANTHROPIC_API_KEY"},
		{"a GitHub token", "token " + gh, gh, "github_token", "GITHUB_TOKEN"},
		{"an AWS key id", "AKIA2E0A8F3B244C9986", "AKIA2E0A8F3B244C9986", "aws_access_key_id", "AWS_ACCESS_KEY_ID"},
		{"a Slack token", "xoxb-" + b(30), "xoxb-" + b(30), "slack_token", "SLACK_TOKEN"},
		{"a Stripe key", "sk_live_" + b(24), "sk_live_" + b(24), "stripe_secret_key", "STRIPE_SECRET_KEY"},
		{"an unknown vendor", "zyq_8fK2mQ7pXvL4nR9sT1wZ3yB6cD0eG5hJ2kM4pQ7rS9t", "zyq_8fK2mQ7pXvL4nR9sT1wZ3yB6cD0eG5hJ2kM4pQ7rS9t", "shaped_api_key", "SECRET"},
		{"NAME=value", "MY_KEY=" + proj, proj, "provider_api_key", "MY_KEY"},
		{"export NAME=value", "export openrouter_key=" + proj, proj, "provider_api_key", "OPENROUTER_KEY"},
		{"NAME: value", "deploy_token: " + gh, gh, "github_token", "DEPLOY_TOKEN"},
		{`"NAME": "value"`, `{"client_secret": "h9Kd2Lm4Nq7Pr1Ts5Vw8Xz3"}`, "h9Kd2Lm4Nq7Pr1Ts5Vw8Xz3", "sensitive_assignment", "CLIENT_SECRET"},
		{"a value named by its keyword", "TWILIO_AUTH_TOKEN=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "sensitive_assignment", "TWILIO_AUTH_TOKEN"},
		{"a URL's password", "DATABASE_URL=postgres://app:Hk29xQm4Lp@db:5432/app", "Hk29xQm4Lp", "url_credentials", "DATABASE_URL"},
		{"a URL's password, unnamed", "connect to postgres://app:Hk29xQm4Lp@db:5432/app", "Hk29xQm4Lp", "url_credentials", "SECRET"},
		{"a Bearer token", "Authorization: Bearer " + b(32), b(32), "bearer_token", "AUTHORIZATION"},
		{"a bare Bearer token", "send Bearer " + b(32), b(32), "bearer_token", "SECRET"},
	}
	for _, c := range cases {
		found := Find(c.text)
		if len(found) != 1 {
			t.Errorf("%s: found %d", c.label, len(found))
			continue
		}
		d := found[0]
		if d.Value != c.value || c.text[d.Start:d.End] != c.value || d.Kind != c.kind || d.SuggestedName != c.name {
			t.Errorf("%s: got %s %s at %d-%d (value matches: %v)", c.label, d.Kind, d.SuggestedName, d.Start, d.End, d.Value == c.value)
		}
	}
}

func TestFindSkipsExamplesAndPlaceholders(t *testing.T) {
	for _, text := range []string{
		"set OPENAI_API_KEY=sk-1234 first",
		"sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		"OPENAI_API_KEY=<your-key>",
		"api_key: <your-key-here>",
		"token ghp_" + strings.Repeat("a", 36),
		"AWS key AKIAIOSFODNN7EXAMPLE from the docs",
		"sk-ant-your-key-goes-here-and-nowhere-else",
		"OPENAI_API_KEY=sk-...",
		"export OPENAI_API_KEY={{vault:OPENAI_API_KEY}}",
		"Use it with `kv run OPENAI_API_KEY -- <cmd>`, never print it.",
	} {
		if found := Find(text); len(found) > 0 {
			t.Errorf("%q: found %s", text, found[0].Kind)
		}
	}
}

func TestFindSeveralSecrets(t *testing.T) {
	proj, gh := "sk-proj-"+b(40), "ghp_"+b(36)
	found := Find("a " + proj + " and b " + gh)
	if len(found) != 2 || found[0].Value != proj || found[1].Value != gh {
		t.Fatalf("found %d", len(found))
	}
}

func TestFindPastTheScanBudget(t *testing.T) {
	proj := "sk-proj-" + b(40)
	text := strings.Repeat("x ", maxScanLength) + "KEY=" + proj
	found := Find(text)
	if len(found) != 1 || text[found[0].Start:found[0].End] != proj || found[0].SuggestedName != "KEY" {
		t.Fatalf("found %d", len(found))
	}
}

func TestUniqueName(t *testing.T) {
	cases := []struct {
		base     string
		existing []string
		want     string
	}{
		{"OPENAI_API_KEY", nil, "OPENAI_API_KEY"},
		{"OPENAI_API_KEY", []string{"OPENAI_API_KEY"}, "OPENAI_API_KEY_2"},
		{"OPENAI_API_KEY", []string{"OPENAI_API_KEY", "OPENAI_API_KEY_2"}, "OPENAI_API_KEY_3"},
		{"SECRET", []string{"OTHER"}, "SECRET"},
	}
	for _, c := range cases {
		if got := UniqueName(c.base, c.existing); got != c.want {
			t.Errorf("UniqueName(%s, %v) = %s, want %s", c.base, c.existing, got, c.want)
		}
	}
}

func TestReplace(t *testing.T) {
	proj := "sk-proj-" + b(40)
	got := Replace("try "+proj+" then again "+proj, proj, "OPENAI_API_KEY")
	want := "try {{vault:OPENAI_API_KEY}} then again {{vault:OPENAI_API_KEY}}" +
		"\n\n({{vault:OPENAI_API_KEY}} is a Kanban vault secret. Use it with `kv run OPENAI_API_KEY -- <cmd>`, never print it.)"
	if got != want {
		t.Errorf("got %q", got)
	}
	if again := Replace(got, proj, "OPENAI_API_KEY"); again != want {
		t.Errorf("a second Replace appended again: %q", again)
	}
	if found := Find(got); len(found) != 0 {
		t.Errorf("the replaced text still has a secret: %s", found[0].Kind)
	}
}
