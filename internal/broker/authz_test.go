package broker

import (
	"strings"
	"testing"

	"github.com/kevinpinscoe/parzival/internal/consumer"
)

const validAuthz = `{
  "schema": 1,
  "entries": [
    { "uid": 1000, "operations": ["tea.repos-list"] }
  ]
}`

func mustParseAuthz(t *testing.T, src string) *AuthzFile {
	t.Helper()
	a, err := Parse([]byte(src), "test-authz.json")
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	return a
}

func authzParseErr(t *testing.T, src string) string {
	t.Helper()
	if _, err := Parse([]byte(src), "test-authz.json"); err != nil {
		return err.Error()
	}
	t.Fatal("Parse: expected an error, got none")
	return ""
}

// --- Parse: strict decode ---------------------------------------------------

func TestAuthzParseAcceptsWellFormed(t *testing.T) {
	a := mustParseAuthz(t, validAuthz)
	if len(a.Entries) != 1 || a.Entries[0].UID != 1000 {
		t.Errorf("Parse: got %+v", a)
	}
}

func TestAuthzParseRejectsUnknownField(t *testing.T) {
	src := `{"schema":1,"entries":[{"uid":1000,"operations":["tea.repos-list"],"gid":100}]}`
	if got := authzParseErr(t, src); !strings.Contains(got, "gid") {
		t.Errorf("error should name the unknown field, got: %s", got)
	}
}

func TestAuthzParseRejectsTrailingData(t *testing.T) {
	src := validAuthz + `{"schema":1,"entries":[]}`
	authzParseErr(t, src)
}

func TestAuthzParseRejectsOmittedSchema(t *testing.T) {
	// Deliberate: unlike consumer.Parse/policy.Parse, an omitted
	// (zero-value) schema is NOT silently treated as current — authz.json is
	// new, with no legacy version to be lenient about.
	src := `{"entries":[{"uid":1000,"operations":["tea.repos-list"]}]}`
	got := authzParseErr(t, src)
	if !strings.Contains(got, "schema 0") {
		t.Errorf("error should name the (omitted, zero-value) schema, got: %s", got)
	}
}

func TestAuthzParseRejectsWrongSchema(t *testing.T) {
	src := `{"schema":2,"entries":[{"uid":1000,"operations":["tea.repos-list"]}]}`
	authzParseErr(t, src)
}

func TestAuthzParseRejectsNoEntries(t *testing.T) {
	src := `{"schema":1,"entries":[]}`
	authzParseErr(t, src)
}

func TestAuthzParseRejectsDuplicateUID(t *testing.T) {
	src := `{"schema":1,"entries":[
		{"uid":1000,"operations":["tea.repos-list"]},
		{"uid":1000,"operations":["tea.repos-list"]}
	]}`
	got := authzParseErr(t, src)
	if !strings.Contains(got, "1000") {
		t.Errorf("error should name the duplicated uid, got: %s", got)
	}
}

func TestAuthzParseRejectsEmptyOperationsInEntry(t *testing.T) {
	src := `{"schema":1,"entries":[{"uid":1000,"operations":[]}]}`
	authzParseErr(t, src)
}

func TestAuthzParseRejectsDuplicateOperationWithinEntry(t *testing.T) {
	src := `{"schema":1,"entries":[{"uid":1000,"operations":["tea.repos-list","tea.repos-list"]}]}`
	authzParseErr(t, src)
}

func TestAuthzParseRejectsMalformedOperationSyntax(t *testing.T) {
	cases := []string{
		`"tea"`,            // no dot
		`"tea."`,           // empty operation half
		`".repos-list"`,    // empty consumer half
		`"tea.repos.list"`, // extra dot
	}
	for _, op := range cases {
		src := `{"schema":1,"entries":[{"uid":1000,"operations":[` + op + `]}]}`
		authzParseErr(t, src)
	}
}

// --- Validate ----------------------------------------------------------------

func teaDefs(t *testing.T) map[string]*consumer.Definition {
	t.Helper()
	d, err := consumer.Parse([]byte(`{
	  "schema": 1,
	  "name": "tea",
	  "executable": "/usr/bin/tea",
	  "profile": "tea",
	  "operations": {
	    "repos-list": {
	      "argv": ["repos", "list", "--owner", "${owner}", "--output", "json"],
	      "inputs": {"owner": {"pattern": "[A-Za-z0-9._-]+", "max_length": 39}},
	      "response": "json"
	    }
	  }
	}`), "tea.json")
	if err != nil {
		t.Fatalf("consumer.Parse: %v", err)
	}
	return map[string]*consumer.Definition{"tea": d}
}

func TestAuthzValidateAcceptsResolvedOperation(t *testing.T) {
	a := mustParseAuthz(t, validAuthz)
	if err := a.Validate(teaDefs(t)); err != nil {
		t.Errorf("Validate: unexpected error: %v", err)
	}
}

func TestAuthzValidateRejectsUnknownConsumer(t *testing.T) {
	a := mustParseAuthz(t, `{"schema":1,"entries":[{"uid":1000,"operations":["nope.repos-list"]}]}`)
	if err := a.Validate(teaDefs(t)); err == nil {
		t.Fatal("Validate: expected an error for an unknown consumer, got none")
	}
}

func TestAuthzValidateRejectsUnknownOperation(t *testing.T) {
	a := mustParseAuthz(t, `{"schema":1,"entries":[{"uid":1000,"operations":["tea.does-not-exist"]}]}`)
	if err := a.Validate(teaDefs(t)); err == nil {
		t.Fatal("Validate: expected an error for an operation not declared by the consumer, got none")
	}
}

// --- Decide: pure, constructed uids ------------------------------------------

func TestAuthzDecide(t *testing.T) {
	a := mustParseAuthz(t, validAuthz) // grants uid 1000 -> tea.repos-list

	cases := []struct {
		uid  uint32
		op   string
		want bool
	}{
		{1000, "tea.repos-list", true},
		{1000, "tea.repos-delete", false}, // authorized uid, different (even nonexistent) operation
		{0, "tea.repos-list", false},      // root, not granted anything
		{4294967295, "tea.repos-list", false},
		{1000, "nope.repos-list", false}, // authorized uid, operation naming a nonexistent consumer
	}
	for _, c := range cases {
		if got := a.Decide(c.uid, c.op); got != c.want {
			t.Errorf("Decide(%d, %q) = %v, want %v", c.uid, c.op, got, c.want)
		}
	}
}

func TestAuthzDecideDoesNotRequireOperationToExist(t *testing.T) {
	// Decide is a pure string match — it must not need a resolved consumer
	// definition. This is what makes the enumeration-safety ordering in
	// session.go possible: authorization can be decided before resolution is
	// even attempted.
	a := mustParseAuthz(t, `{"schema":1,"entries":[{"uid":1000,"operations":["ghost.does-not-exist"]}]}`)
	if !a.Decide(1000, "ghost.does-not-exist") {
		t.Error("Decide: should authorize a syntactically valid operation string regardless of whether it resolves")
	}
}
