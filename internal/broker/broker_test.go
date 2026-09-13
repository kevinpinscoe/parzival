package broker

import (
	"errors"
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/store"
)

func TestNewServerAcceptsValidFixture(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{})
	if srv == nil {
		t.Fatal("newTestServer: got nil Server")
	}
	if len(srv.defs) != 1 || srv.defs["tea"] == nil {
		t.Errorf("newServer: consumer definitions not loaded as expected: %+v", srv.defs)
	}
	if len(srv.profiles) != 1 || srv.profiles["tea"] == nil {
		t.Errorf("newServer: profiles not loaded as expected: %+v", srv.profiles)
	}
}

// newFailingServer is like newTestServer but calls newServer directly and
// returns the error instead of failing the test, for the refusal tests
// below.
func newFailingServer(t *testing.T, authzPath string, verify verifyTrustRootFunc) error {
	t.Helper()
	cfg := Config{
		SocketPath: filepath.Join(t.TempDir(), "broker.sock"),
		AuthzPath:  authzPath,
		AuditPath:  filepath.Join(t.TempDir(), "audit.log"),
	}
	resolve := func(store.SecretRef) (store.Store, error) { return &fakeSecretStore{values: defaultTestSecrets()}, nil }
	peer := func(*net.UnixConn) (uint32, error) { return authorizedTestUID, nil }
	_, err := newServer(cfg, verify, resolve, peer, time.Now, &fakeAuditWriter{}, log.New(io.Discard, "", 0))
	return err
}

func TestNewServerRefusesOnConsumerDefinitionTrustRootFailure(t *testing.T) {
	authzPath := testEnv(t)
	verify := func(path string, uid uint32) error {
		if strings.Contains(path, "consumers") {
			return errors.New("fake: consumer definition is agent-writable")
		}
		return nil
	}
	if err := newFailingServer(t, authzPath, verify); err == nil {
		t.Fatal("newServer: expected refusal on a failing consumer-definition trust-root check, got none")
	}
}

func TestNewServerRefusesOnConsumerExecutableTrustRootFailure(t *testing.T) {
	authzPath := testEnv(t)
	verify := func(path string, uid uint32) error {
		if strings.Contains(path, "faketea") {
			return errors.New("fake: consumer executable is agent-writable")
		}
		return nil
	}
	if err := newFailingServer(t, authzPath, verify); err == nil {
		t.Fatal("newServer: expected refusal on a failing executable trust-root check, got none")
	}
}

func TestNewServerRefusesOnProfileTrustRootFailure(t *testing.T) {
	authzPath := testEnv(t)
	verify := func(path string, uid uint32) error {
		if strings.Contains(path, "profiles") {
			return errors.New("fake: profile is agent-writable")
		}
		return nil
	}
	if err := newFailingServer(t, authzPath, verify); err == nil {
		t.Fatal("newServer: expected refusal on a failing profile trust-root check, got none")
	}
}

func TestNewServerRefusesOnAuthzTrustRootFailure(t *testing.T) {
	authzPath := testEnv(t)
	verify := func(path string, uid uint32) error {
		if path == authzPath {
			return errors.New("fake: authorization file is agent-writable")
		}
		return nil
	}
	if err := newFailingServer(t, authzPath, verify); err == nil {
		t.Fatal("newServer: expected refusal on a failing authorization-file trust-root check, got none")
	}
}

func TestNewServerRefusesOnMissingProfile(t *testing.T) {
	authzPath := testEnv(t)
	// Remove the profile the consumer definition references.
	profilePath := filepath.Join(configHomeFromEnv(t), "profiles", "tea.json")
	removeFile(t, profilePath)

	if err := newFailingServer(t, authzPath, noopVerify); err == nil {
		t.Fatal("newServer: expected refusal when a referenced profile is missing, got none")
	}
}

func TestNewServerRefusesOnProfileClaimingReservedEnvVar(t *testing.T) {
	authzPath := testEnv(t)
	profilePath := filepath.Join(configHomeFromEnv(t), "profiles", "tea.json")
	writeFile(t, profilePath, `{
	  "secrets": {"token": "bao:app/gitea#token"},
	  "template": "token: {{ .token }}\n",
	  "inject": {"env": "PATH"}
	}`)

	if err := newFailingServer(t, authzPath, noopVerify); err == nil {
		t.Fatal("newServer: expected refusal when a profile's Inject.Env claims a reserved variable (PATH), got none")
	}
}

func TestNewServerRefusesOnProfileClaimingBaoPrefixedVar(t *testing.T) {
	authzPath := testEnv(t)
	profilePath := filepath.Join(configHomeFromEnv(t), "profiles", "tea.json")
	writeFile(t, profilePath, `{
	  "secrets": {"token": "bao:app/gitea#token"},
	  "template": "token: {{ .token }}\n",
	  "inject": {"env_dir": "BAO_ADDR"}
	}`)

	if err := newFailingServer(t, authzPath, noopVerify); err == nil {
		t.Fatal("newServer: expected refusal when a profile's Inject.EnvDir claims a BAO_-prefixed variable, got none")
	}
}

func TestNewServerRefusesOnAuthzValidationFailure(t *testing.T) {
	authzPath := testEnv(t)
	// Overwrite the fixture authz file with one authorizing an operation no
	// loaded consumer declares.
	writeFile(t, authzPath, `{"schema":1,"entries":[{"uid":1000,"operations":["tea.does-not-exist"]}]}`)

	if err := newFailingServer(t, authzPath, noopVerify); err == nil {
		t.Fatal("newServer: expected refusal when the authorization file names an operation no consumer declares, got none")
	}
}

func TestNewServerRefusesOnOperationWithNoResponseValidator(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", configHome)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	consumersDir := filepath.Join(configHome, "consumers")
	profilesDir := filepath.Join(configHome, "profiles")
	mkdirAll(t, consumersDir)
	mkdirAll(t, profilesDir)
	writeFile(t, filepath.Join(consumersDir, "tea.json"), `{
	  "schema": 1, "name": "tea", "executable": "`+fakeTeaPath+`", "profile": "tea",
	  "operations": {"repos-delete": {"argv": ["x"], "response": "text"}}
	}`)
	writeFile(t, filepath.Join(profilesDir, "tea.json"), testProfileJSON)
	authzPath := filepath.Join(t.TempDir(), "authz.json")
	writeFile(t, authzPath, `{"schema":1,"entries":[{"uid":1000,"operations":["tea.repos-delete"]}]}`)

	if err := newFailingServer(t, authzPath, noopVerify); err == nil {
		t.Fatal("newServer: expected refusal for a declared operation with no registered response validator, got none")
	}
}
