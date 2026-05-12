package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gowa "github.com/go-webauthn/webauthn/webauthn"

	"github.com/framefilter/bubbleui/backend/internal/auth"
	bcrypto "github.com/framefilter/bubbleui/backend/internal/crypto"
	"github.com/framefilter/bubbleui/backend/internal/session"
	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/webauthn"
)

type testRig struct {
	server   *httptest.Server
	store    *store.Store
	auth     *auth.Authenticator
	sessions *session.Manager
	setTime  func(t time.Time) error
	timeMu   sync.Mutex
	lastSet  time.Time
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	a := auth.New(s)

	// Every rig gets a WebAuthn engine — the new endpoints assume one is
	// configured, and crypto-free tests still need it to route correctly.
	eng, err := webauthn.New(webauthn.Config{
		RPID:          "bubble.local",
		RPDisplayName: "BubbleUI test",
		Origins:       []string{"https://bubble.local"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	a.WebAuthn = eng

	mgr, err := session.NewManager(context.Background(), s.DB())
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	rig := &testRig{store: s, auth: a, sessions: mgr}
	rig.setTime = func(tm time.Time) error {
		rig.timeMu.Lock()
		rig.lastSet = tm
		rig.timeMu.Unlock()
		return nil
	}

	srv := New(Config{
		Auth:          a,
		Sessions:      mgr,
		Insecure:      true, // httptest is plain HTTP
		SetSystemTime: rig.setTime,
	})
	rig.server = httptest.NewServer(srv)
	t.Cleanup(rig.server.Close)
	return rig
}

func (rig *testRig) client(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

// seedWebAuthnCredential plants a fake WebAuthn credential row in the
// store. The cryptographic fields are nonsense — good enough for
// endpoints that only check existence or echo allowed-credential IDs.
func (rig *testRig) seedWebAuthnCredential(t *testing.T) int64 {
	t.Helper()
	id, err := rig.store.AddCredential(context.Background(), store.Credential{
		Kind:           store.KindWebAuthn,
		Label:          "fake",
		CredentialID:   []byte("demo-cred"),
		PublicMaterial: fakeWebAuthnCredentialBlob(t, []byte("demo-cred")),
	})
	if err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	return id
}

// seedRecoveryCode plants a recovery code in the store and returns the
// plaintext to the caller. Mirrors what FinishRegisterWebAuthn does on
// the first credential registration.
func (rig *testRig) seedRecoveryCode(t *testing.T) string {
	t.Helper()
	code, err := bcrypto.NewRecoveryCode()
	if err != nil {
		t.Fatalf("NewRecoveryCode: %v", err)
	}
	hashed, err := bcrypto.HashRecoveryCode(code)
	if err != nil {
		t.Fatalf("HashRecoveryCode: %v", err)
	}
	if err := rig.store.SetRecoveryCodeHash(context.Background(), hashed); err != nil {
		t.Fatalf("SetRecoveryCodeHash: %v", err)
	}
	return code
}

// loginAs mints a session for credID and installs the cookie on c so
// subsequent requests look authenticated. Used as a shortcut around the
// real WebAuthn ceremony, which we can't run in unit tests.
func (rig *testRig) loginAs(t *testing.T, c *http.Client, credID int64) {
	t.Helper()
	token, sess, err := rig.sessions.Create(context.Background(), credID)
	if err != nil {
		t.Fatalf("session.Create: %v", err)
	}
	u, _ := http.NewRequest("GET", rig.server.URL, nil)
	c.Jar.SetCookies(u.URL, []*http.Cookie{{
		Name:    session.CookieName,
		Value:   token,
		Path:    "/",
		Expires: sess.ExpiresAt,
	}})
}

func decodeJSON(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return m
}

func TestWhoamiUnauthenticated(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	resp, err := c.Get(rig.server.URL + "/auth/session/whoami")
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["authenticated"] != false {
		t.Fatalf("expected authenticated=false, got %v", body)
	}
}

func TestWhoamiAuthenticated(t *testing.T) {
	rig := newRig(t)
	credID := rig.seedWebAuthnCredential(t)
	c := rig.client(t)
	rig.loginAs(t, c, credID)

	resp, err := c.Get(rig.server.URL + "/auth/session/whoami")
	if err != nil {
		t.Fatalf("GET whoami: %v", err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["authenticated"] != true {
		t.Fatalf("expected authenticated=true, got %v", body)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	rig := newRig(t)
	credID := rig.seedWebAuthnCredential(t)
	c := rig.client(t)
	rig.loginAs(t, c, credID)

	logoutResp, err := c.Post(rig.server.URL+"/auth/session/logout", "", nil)
	if err != nil {
		t.Fatalf("POST logout: %v", err)
	}
	logoutResp.Body.Close()

	resp, err := c.Get(rig.server.URL + "/auth/session/whoami")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["authenticated"] != false {
		t.Fatalf("expected unauthenticated post-logout, got %v", body)
	}
}

func TestRecoverEndpoint(t *testing.T) {
	rig := newRig(t)
	credID := rig.seedWebAuthnCredential(t)
	code := rig.seedRecoveryCode(t)
	c := rig.client(t)

	// Start a session, then recover — recover must invalidate it.
	rig.loginAs(t, c, credID)

	resp, err := c.Post(rig.server.URL+"/auth/recover", "application/json",
		strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil {
		t.Fatalf("POST recover: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recover status = %d, want 200", resp.StatusCode)
	}

	whoamiResp, err := c.Get(rig.server.URL + "/auth/session/whoami")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer whoamiResp.Body.Close()
	body := decodeJSON(t, whoamiResp.Body)
	if body["authenticated"] != false {
		t.Fatalf("expected unauthenticated post-recover, got %v", body)
	}
}

func TestRecoverRejectsBadCode(t *testing.T) {
	rig := newRig(t)
	_ = rig.seedRecoveryCode(t)
	c := rig.client(t)

	resp, err := c.Post(rig.server.URL+"/auth/recover", "application/json",
		strings.NewReader(`{"code":"NOPE-NOPE-NOPE-NOPE-NOPE"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestRecoverRequiresCode(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	resp, err := c.Post(rig.server.URL+"/auth/recover", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTimeSyncWithinTolerance(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	now := time.Now()
	resp, err := c.Post(rig.server.URL+"/api/time/sync", "application/json",
		strings.NewReader(`{"now":`+jsonInt(now.UnixMilli())+`}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["action"] != "accepted" {
		t.Fatalf("expected accepted, got %v", body)
	}
	rig.timeMu.Lock()
	defer rig.timeMu.Unlock()
	if !rig.lastSet.IsZero() {
		t.Fatal("setTime should not have been called within tolerance")
	}
}

func TestTimeSyncOutOfTolerancePromptsBeforeApplying(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	future := time.Now().Add(48 * time.Hour)

	// Without force=true, the daemon must report skew but not apply.
	resp, err := c.Post(rig.server.URL+"/api/time/sync", "application/json",
		strings.NewReader(`{"now":`+jsonInt(future.UnixMilli())+`}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["action"] != "skew_detected" {
		t.Fatalf("expected skew_detected, got %v", body)
	}
	rig.timeMu.Lock()
	if !rig.lastSet.IsZero() {
		rig.timeMu.Unlock()
		t.Fatal("setTime called without force=true")
	}
	rig.timeMu.Unlock()

	// With force=true, apply.
	resp2, err := c.Post(rig.server.URL+"/api/time/sync", "application/json",
		strings.NewReader(`{"now":`+jsonInt(future.UnixMilli())+`,"force":true}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp2.Body.Close()
	body2 := decodeJSON(t, resp2.Body)
	if body2["action"] != "applied" {
		t.Fatalf("expected applied with force, got %v", body2)
	}
	rig.timeMu.Lock()
	defer rig.timeMu.Unlock()
	if rig.lastSet.IsZero() {
		t.Fatal("expected setTime to have been called with force=true")
	}
}

func TestTimeSyncForceWithoutHookReturns503(t *testing.T) {
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	a := auth.New(s)
	mgr, _ := session.NewManager(context.Background(), s.DB())
	srv := New(Config{Auth: a, Sessions: mgr, Insecure: true /* SetSystemTime: nil */})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	future := time.Now().Add(48 * time.Hour)
	resp, err := http.Post(ts.URL+"/api/time/sync", "application/json",
		strings.NewReader(`{"now":`+jsonInt(future.UnixMilli())+`,"force":true}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestTimeSyncRejectsBadInput(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	for _, body := range []string{`{}`, `{"now":-1}`, `not-json`} {
		resp, err := c.Post(rig.server.URL+"/api/time/sync", "application/json", strings.NewReader(body))
		if err != nil {
			t.Errorf("body=%q: POST: %v", body, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body=%q: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	resp, err := c.Get(rig.server.URL + "/auth/session/whoami")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
}

func TestOriginCheckBlocksDisallowed(t *testing.T) {
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	a := auth.New(s)
	mgr, _ := session.NewManager(context.Background(), s.DB())
	srv := New(Config{
		Auth:           a,
		Sessions:       mgr,
		Insecure:       true,
		AllowedOrigins: []string{"https://bubble.local"},
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Use /auth/recover (still a state-changing POST) to drive the
	// origin check. The endpoint's body validation will reject the
	// payload on the allowed-origin path, but only after the origin
	// gate has been cleared — that's the order we want to verify.
	req, _ := http.NewRequest("POST", ts.URL+"/auth/recover", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed origin: status = %d, want 403", resp.StatusCode)
	}

	req2, _ := http.NewRequest("POST", ts.URL+"/auth/recover", strings.NewReader(`{}`))
	req2.Header.Set("Origin", "https://bubble.local")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusForbidden {
		t.Fatalf("allowed origin got 403")
	}
}

func TestSetupStatusReflectsCredentialCount(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)

	resp, err := c.Get(rig.server.URL + "/auth/setup-status")
	if err != nil {
		t.Fatal(err)
	}
	body := decodeJSON(t, resp.Body)
	resp.Body.Close()
	if body["has_credentials"] != false {
		t.Fatalf("fresh device: expected has_credentials=false, got %v", body)
	}

	rig.seedWebAuthnCredential(t)

	resp2, err := c.Get(rig.server.URL + "/auth/setup-status")
	if err != nil {
		t.Fatal(err)
	}
	body = decodeJSON(t, resp2.Body)
	resp2.Body.Close()
	if body["has_credentials"] != true {
		t.Fatalf("post-seed: expected has_credentials=true, got %v", body)
	}
}

func TestHealthReportsCredentialState(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)

	resp, err := c.Get(rig.server.URL + "/auth/health")
	if err != nil {
		t.Fatal(err)
	}
	body := decodeJSON(t, resp.Body)
	resp.Body.Close()
	if body["has_credentials"] != false {
		t.Errorf("fresh: has_credentials = %v", body["has_credentials"])
	}

	rig.seedWebAuthnCredential(t)
	resp2, err := c.Get(rig.server.URL + "/auth/health")
	if err != nil {
		t.Fatal(err)
	}
	body = decodeJSON(t, resp2.Body)
	resp2.Body.Close()
	if body["has_credentials"] != true {
		t.Errorf("post-seed: has_credentials = %v", body["has_credentials"])
	}
}

// --- WebAuthn endpoint tests ---

func fakeWebAuthnCredentialBlob(t *testing.T, id []byte) []byte {
	t.Helper()
	c := gowa.Credential{
		ID:              id,
		PublicKey:       []byte{0xa5, 0x01, 0x02, 0x03},
		AttestationType: "none",
	}
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return blob
}

func TestWebAuthnRegisterBeginBootstrapAllowed(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)

	// No credentials registered → bootstrap mode → register/begin should succeed.
	resp, err := c.Post(rig.server.URL+"/auth/webauthn/register/begin", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["handle"] == nil || body["handle"] == "" {
		t.Fatalf("missing handle: %v", body)
	}
	if body["options"] == nil {
		t.Fatalf("missing options: %v", body)
	}
}

func TestWebAuthnRegisterBeginRequiresAuthOnceCredentialExists(t *testing.T) {
	rig := newRig(t)
	credID := rig.seedWebAuthnCredential(t)

	c := rig.client(t)
	resp, err := c.Post(rig.server.URL+"/auth/webauthn/register/begin", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	rig.loginAs(t, c, credID)
	resp2, err := c.Post(rig.server.URL+"/auth/webauthn/register/begin", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authed register/begin: status = %d, want 200", resp2.StatusCode)
	}
}

func TestWebAuthnRegisterFinishRejectsBogusBody(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)

	beginResp, err := c.Post(rig.server.URL+"/auth/webauthn/register/begin", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer beginResp.Body.Close()
	begin := decodeJSON(t, beginResp.Body)

	finishBody := map[string]any{
		"handle":   begin["handle"],
		"response": map[string]any{"id": "x", "rawId": "x"},
	}
	bodyBytes, _ := json.Marshal(finishBody)

	resp, err := c.Post(rig.server.URL+"/auth/webauthn/register/finish", "application/json",
		strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebAuthnRegisterFinishRequiresHandleAndResponse(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	for _, body := range []string{`{}`, `{"handle":""}`, `{"response":{}}`, `not-json`} {
		resp, err := c.Post(rig.server.URL+"/auth/webauthn/register/finish", "application/json",
			strings.NewReader(body))
		if err != nil {
			t.Errorf("body=%q: %v", body, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body=%q: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestWebAuthnLoginBeginRejectsWithoutCredentials(t *testing.T) {
	rig := newRig(t)
	c := rig.client(t)
	resp, err := c.Post(rig.server.URL+"/auth/webauthn/login/begin", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebAuthnLoginBeginAllowsWithRegisteredCredential(t *testing.T) {
	rig := newRig(t)
	rig.seedWebAuthnCredential(t)

	c := rig.client(t)
	resp, err := c.Post(rig.server.URL+"/auth/webauthn/login/begin", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestWebAuthnLoginFinishRejectsBogusBody(t *testing.T) {
	rig := newRig(t)
	rig.seedWebAuthnCredential(t)

	c := rig.client(t)
	beginResp, _ := c.Post(rig.server.URL+"/auth/webauthn/login/begin", "application/json",
		strings.NewReader(`{}`))
	begin := decodeJSON(t, beginResp.Body)
	beginResp.Body.Close()

	body := map[string]any{
		"handle":   begin["handle"],
		"response": map[string]any{"id": "x", "rawId": "x"},
	}
	bodyBytes, _ := json.Marshal(body)
	resp, err := c.Post(rig.server.URL+"/auth/webauthn/login/finish", "application/json",
		strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func jsonInt(n int64) string {
	out := "0"
	if n != 0 {
		neg := n < 0
		if neg {
			n = -n
		}
		out = ""
		for n > 0 {
			out = string(rune('0'+(n%10))) + out
			n /= 10
		}
		if neg {
			out = "-" + out
		}
	}
	return out
}
