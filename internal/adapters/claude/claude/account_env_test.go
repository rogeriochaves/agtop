package claude

import (
	"strings"
	"testing"
)

func TestEnvDropsTheTraceContextItWasStartedIn(t *testing.T) {
	t.Setenv("TRACEPARENT", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	t.Setenv("TRACESTATE", "lw=1")
	t.Setenv("RUSH_TEST_KEPT", "yes")
	kept := false
	for _, e := range (Account{}).Env() {
		name, _, _ := strings.Cut(e, "=")
		if name == "TRACEPARENT" || name == "TRACESTATE" {
			t.Fatalf("Env() passed on %s", name)
		}
		if e == "RUSH_TEST_KEPT=yes" {
			kept = true
		}
	}
	if !kept {
		t.Fatal("Env() dropped an ordinary variable")
	}
}
