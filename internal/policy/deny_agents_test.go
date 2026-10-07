package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the per-rule deny_agents field (PARZIVAL-84). The field changes a
// matching allow-rule's decision for a request from a detected AI agent
// context, and nothing else: it never changes whether a rule matches.

func mustParse(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte(body), "test-policy.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

var denyAgentsAt = time.Date(2026, 10, 7, 9, 0, 0, 0, time.Local)

func req(ref, id, mode, agent string) Request {
	return Request{Ref: ref, Identity: id, Mode: mode, Time: denyAgentsAt, Agent: agent}
}

// An agent-denying rule placed above a broad allow: the shape the field is for.
const agentDenyThenBroadAllow = `{
  "schema": 1,
  "rules": [
    { "allow": true, "deny_agents": true, "description": "admin token, refused to agent contexts",
      "secrets": ["bao:app/admin#token"], "modes": ["exec","mount"] },
    { "allow": true, "description": "broad brokered fallback", "secrets": ["bao:app/*"], "modes": ["exec","mount"] }
  ]
}`

func TestDenyAgentsAllowsANonAgentRequest(t *testing.T) {
	p := mustParse(t, agentDenyThenBroadAllow)
	d := p.Evaluate(req("bao:app/admin#token", "kevin", ModeExec, ""))
	if !d.Allow || d.AgentDenied {
		t.Fatalf("non-agent request: got %+v, want allow by rule 0", d)
	}
	if d.Reason != "rule 0" {
		t.Errorf("reason %q, want %q", d.Reason, "rule 0")
	}
}

func TestDenyAgentsDeniesAnAgentRequest(t *testing.T) {
	p := mustParse(t, agentDenyThenBroadAllow)
	d := p.Evaluate(req("bao:app/admin#token", "kevin", ModeExec, "CLAUDECODE"))
	if d.Allow || !d.AgentDenied {
		t.Fatalf("agent request: got %+v, want an agent denial", d)
	}
	if !strings.Contains(d.Reason, "rule 0") || !strings.Contains(d.Reason, "CLAUDECODE") {
		t.Errorf("reason %q should name the rule and the marker", d.Reason)
	}
}

// The rule still matches for an agent, so evaluation stops there: the broad
// rule below it — which does match and does allow — is never consulted.
func TestDenyAgentsBlocksALaterBroadAllow(t *testing.T) {
	p := mustParse(t, agentDenyThenBroadAllow)
	allow, idx := p.Explain(req("bao:app/admin#token", "ai", ModeExec, "CLAUDECODE"))
	if allow || idx != 0 {
		t.Fatalf("agent request decided by rule %d allow=%v, want rule 0 deny", idx, allow)
	}
	// The broad rule is still in force for refs the agent-denying rule does not cover.
	if allow, idx := p.Explain(req("bao:app/gitea#token", "ai", ModeExec, "CLAUDECODE")); !allow || idx != 1 {
		t.Errorf("unrelated ref: got rule %d allow=%v, want rule 1 allow", idx, allow)
	}
}

// An identity-independent agent-denying rule cannot be routed around by
// asserting a different --as label: every label matches it.
func TestDenyAgentsCannotBeBypassedByChangingIdentity(t *testing.T) {
	p := mustParse(t, agentDenyThenBroadAllow)
	for _, id := range []string{"", "kevin", "admin", "ai", "codex", "human", "*"} {
		d := p.Evaluate(req("bao:app/admin#token", id, ModeExec, "PARZIVAL_AGENT"))
		if d.Allow {
			t.Errorf("--as %q: allowed, want the agent denial to hold for every label", id)
		}
	}
}

// Every mode the rule matches is covered, not exec alone.
func TestDenyAgentsAppliesToEveryMatchedMode(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"] }
	]}`)
	for _, m := range []string{ModeGet, ModeExec, ModeMount} {
		if p.Evaluate(req("bao:app/admin#token", "kevin", m, "AI_AGENT")).Allow {
			t.Errorf("mode %s: agent allowed", m)
		}
		if !p.Evaluate(req("bao:app/admin#token", "kevin", m, "")).Allow {
			t.Errorf("mode %s: non-agent denied", m)
		}
	}
}

// A rule without the field decides an agent request exactly as it decides any
// other — ordinary brokered use by an agent is unchanged.
func TestOrdinaryRuleIsUnchangedForAgents(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": true, "secrets": ["bao:app/gitea#*"], "identities": ["ai"], "modes": ["exec","mount"] }
	]}`)
	for _, agent := range []string{"", "CLAUDECODE"} {
		if d := p.Evaluate(req("bao:app/gitea#token", "ai", ModeExec, agent)); !d.Allow || d.AgentDenied {
			t.Errorf("agent=%q: got %+v, want allow", agent, d)
		}
		if d := p.Evaluate(req("bao:app/gitea#token", "ai", ModeGet, agent)); d.Allow {
			t.Errorf("agent=%q get: allowed, want the mode restriction to hold", agent)
		}
	}
}

// The documented first-match limit: an earlier allow that matches the request
// decides before the agent-denying rule is reached. The analysis must report
// that the denial never takes effect.
func TestEarlierAllowWinsOverALaterAgentDenial(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": true, "secrets": ["bao:app/admin#token"], "identities": ["ai"] },
	  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"] }
	]}`)
	if !p.Evaluate(req("bao:app/admin#token", "ai", ModeExec, "CLAUDECODE")).Allow {
		t.Fatal("first match should decide: rule 0 allows")
	}
	a := p.Analyze()
	// Rule 0 does not fully cover rule 1 (it is identity-scoped), so this is a
	// partial overlap that differs only for agents: a shadowing warning.
	f := findKind(a, FindingShadows)
	if f == nil {
		t.Fatalf("no shadows finding; got %+v", a.Findings)
	}
	if !strings.Contains(f.Message, "for agent contexts") {
		t.Errorf("message should name the agent context: %s", f.Message)
	}
}

func TestEarlierCoveringAllowMakesAgentDenialUnreachable(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": true, "secrets": ["bao:app/*"] },
	  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"] }
	]}`)
	f := findKind(p.Analyze(), FindingUnreachable)
	if f == nil || f.Rule != 1 || f.Severity != SeverityError {
		t.Fatalf("want an unreachable error on rule 1, got %+v", f)
	}
	if !strings.Contains(f.Message, "for agent contexts") || !strings.Contains(f.Message, "deny_agents") {
		t.Errorf("message should say the agent denial never takes effect: %s", f.Message)
	}
	if findKind(p.Analyze(), FindingRedundant) != nil {
		t.Error("a rule whose agent outcome differs must not be called redundant")
	}
}

func TestIdenticalAgentDenyingRulesAreRedundant(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"] },
	  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"] }
	]}`)
	a := p.Analyze()
	if findKind(a, FindingRedundant) == nil || findKind(a, FindingUnreachable) != nil {
		t.Errorf("want redundant and no unreachable, got %+v", a.Findings)
	}
}

// An agent-denying rule above a broad allow it partially overlaps is the
// intended shape. It is reported as shadowing for agents — a warning — and is
// not an error.
func TestAgentDenialAboveBroadAllowIsAWarningOnly(t *testing.T) {
	a := mustParse(t, agentDenyThenBroadAllow).Analyze()
	if !a.OK() {
		t.Fatalf("intended shape reported errors: %+v", a.Errors())
	}
	f := findKind(a, FindingShadows)
	if f == nil || !strings.Contains(f.Message, "for agent contexts") {
		t.Errorf("want an agent-context shadows warning, got %+v", f)
	}
}

func TestDenyAgentsOnADenyRuleWarns(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": false, "deny_agents": true, "secrets": ["bao:app/admin#token"] }
	]}`)
	a := p.Analyze()
	f := findKind(a, FindingDenyAgentsNoop)
	if f == nil || f.Severity != SeverityWarning {
		t.Fatalf("want a deny-agents-noop warning, got %+v", a.Findings)
	}
	if !a.OK() {
		t.Error("a no-op field must not block")
	}
}

func TestIdentityScopedAgentDenialWarns(t *testing.T) {
	p := mustParse(t, `{"rules": [
	  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"], "identities": ["kevin"] }
	]}`)
	if f := findKind(p.Analyze(), FindingDenyAgentsIdentityScoped); f == nil {
		t.Fatal("want a deny-agents-identity-scoped warning")
	}
	q := mustParse(t, agentDenyThenBroadAllow)
	if f := findKind(q.Analyze(), FindingDenyAgentsIdentityScoped); f != nil {
		t.Errorf("identity-independent rule warned: %s", f.Message)
	}
}

func TestDenyAgentsMustBeABoolean(t *testing.T) {
	if _, err := Parse([]byte(`{"rules":[{"allow":true,"deny_agents":"yes"}]}`), "x.json"); err == nil {
		t.Error("a non-boolean deny_agents was accepted")
	}
}

// --- delta -----------------------------------------------------------------

func TestProbeSetAddsAgentProbesOnlyWhenTheyCanMatter(t *testing.T) {
	plain := mustParse(t, `{"rules":[{"allow":true,"secrets":["bao:x"]}]}`)
	for _, pr := range ProbeSet([]*Policy{plain}, nil) {
		if pr.Agent {
			t.Fatal("agent probe added for a policy with no deny_agents rule")
		}
	}
	withDeny := mustParse(t, agentDenyThenBroadAllow)
	agents := 0
	for _, pr := range ProbeSet([]*Policy{withDeny}, nil) {
		if pr.Agent {
			agents++
		}
	}
	if agents == 0 {
		t.Fatal("no agent probes for a policy that sets deny_agents")
	}
}

func TestDeltaReportsAnAgentOnlyRevocation(t *testing.T) {
	before := mustParse(t, `{"rules":[{"allow":true,"secrets":["bao:app/*"],"modes":["exec","mount"]}]}`)
	after := mustParse(t, agentDenyThenBroadAllow)
	d := DiffAuthorization(before, after, ProbeSet([]*Policy{before, after}, nil), denyAgentsAt)
	revoked := d.Revocations()
	if len(revoked) == 0 {
		t.Fatal("adding deny_agents revoked nothing")
	}
	for _, c := range revoked {
		if !c.Probe.Agent {
			t.Errorf("non-agent request revoked: %s", c.Describe())
		}
		if c.Probe.Ref != "bao:app/admin#token" {
			t.Errorf("unexpected ref revoked: %s", c.Describe())
		}
	}
}

func TestUnexpectedAcceptsTheAgentCounterpartOfAnExpectedGrant(t *testing.T) {
	before := mustParse(t, agentDenyThenBroadAllow)
	grant := Rule{Allow: true, Secrets: []string{"bao:other#token"}, Identities: []string{"ai"}, Modes: []string{ModeExec}}
	after := mustParse(t, agentDenyThenBroadAllow)
	after.Rules = append(after.Rules, grant)
	want := RuleProbes(grant)
	d := DiffAuthorization(before, after, ProbeSet([]*Policy{before, after}, want), denyAgentsAt)
	if un := d.Unexpected(want); len(un) != 0 {
		for _, c := range un {
			t.Errorf("unexpected side effect: %s", c.Describe())
		}
	}
}

// --- audit and errors ------------------------------------------------------

func TestAuditRecordsTheAgentMarker(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	writeAudit(req("bao:x", "kevin", ModeExec, "CLAUDECODE"), "DENY", "rule 0 denies agent contexts")
	writeAudit(req("bao:x", "kevin", ModeExec, ""), "ALLOW", "rule 0")
	data, err := os.ReadFile(filepath.Join(state, "parzival", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "\tagent=CLAUDECODE") {
		t.Errorf("agent line lacks the marker: %s", lines[0])
	}
	if strings.Contains(lines[1], "agent=") {
		t.Errorf("non-agent line carries an agent field: %s", lines[1])
	}
}

func TestDeniedErrorExplainsAnAgentDenial(t *testing.T) {
	e := &DeniedError{Req: req("bao:x", "kevin", ModeExec, "CLAUDECODE"), Reason: "rule 0 denies agent contexts", AgentDenied: true}
	msg := e.Error()
	if !strings.Contains(msg, "deny_agents") || !strings.Contains(msg, "--as") {
		t.Errorf("message does not explain the agent denial: %s", msg)
	}
	if strings.Contains(msg, "human") && strings.Contains(msg, "authenticat") {
		t.Errorf("message must not claim human authentication: %s", msg)
	}
}

func findKind(a Analysis, kind string) *Finding {
	for i := range a.Findings {
		if a.Findings[i].Kind == kind {
			return &a.Findings[i]
		}
	}
	return nil
}
