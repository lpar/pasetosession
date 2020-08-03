package pasetosession_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lpar/blammo/log"
	"github.com/o1egl/paseto"
	flag "github.com/spf13/pflag"

	"github.com/lpar/pasetosession"
)

const testIssuer = "testIssuer"
const testAudience = "testAudience"
const testSubject = "login@example.com"
const testEmail = "john.smith@example.com"
const testName = "John Q. Smith Esq."
const testCookieName = "TestSessionCookie"
const testLifespan = time.Minute

var debug = flag.Bool("debug", false, "turn on debug logging")

var sessMgr = pasetosession.NewSessionManager("chunkybacon", testLifespan)

func TestMain(m *testing.M) {
	sessMgr.Issuer = testIssuer
	sessMgr.Audience = testAudience
	sessMgr.CookieName = testCookieName

	ds := os.Getenv("DEBUG")
	if ds == "true" || ds == "1" || *debug {
		log.SetDebug(true)
	}
	os.Exit(m.Run())
}

func TestToken(t *testing.T) {
	s, strtok, err := makeTestData(t)
	if err != nil {
		t.Fatalf("failed to create test data")
	}
	ntok, err := s.DecodeToken(strtok, false)
	verifyOutcome(ntok, err, t)
	_, err = s.DecodeToken(strtok, false)
	if err == nil {
		t.Errorf("duplicate token decode allowed")
	} else {
		log.Debug().Err(err).Msg("duplicate decode attempted")
	}
}

func TestTokenReuse(t *testing.T) {
	s, strtok, err := makeTestData(t)
	if err != nil {
		t.Fatalf("failed to create test data")
	}
	ntok, err := s.DecodeToken(strtok, true)
	verifyOutcome(ntok, err, t)
	_, err = s.DecodeToken(strtok, false)
	if err != nil {
		t.Errorf("token reuse was not allowed")
	}
	verifyOutcome(ntok, err, t)
}

func makeTestData(t *testing.T) (*pasetosession.SessionManager, string, error) {
	s := pasetosession.NewSessionManager("chunky bacon", 1*time.Minute)
	s.Audience = testAudience
	s.Issuer = testIssuer
	tok := &paseto.JSONToken{}
	tok.Set("name", testName)
	tok.Set("email", testEmail)
	strtok, err := s.EncodeToken(testSubject, tok)
	if err != nil {
		t.Errorf("failed to encode token: %v", err)
	}
	if strtok == "" {
		t.Errorf("failed to encode token, empty string returned: %v", err)
	}
	if tok.Audience != "" || tok.Subject != "" || tok.Issuer != "" {
		t.Errorf("call to EncodeToken mutated token argument")
	}
	log.Debug().Str("token", strtok).Msg("encoded token")
	return s, strtok, err
}

func verifyOutcome(ntok *paseto.JSONToken, err error, t *testing.T) {
	log.Debug().Str("audience", ntok.Audience).Str("issuer", ntok.Issuer).Str("subject", ntok.Subject).Msg("decoded token")
	if err != nil {
		t.Errorf("failed to decode token: %v", err)
	}
	if ntok.Audience != testAudience {
		t.Errorf("audience corrupted, expected %s got %s", testAudience, ntok.Audience)
	}
	if ntok.Issuer != testIssuer {
		t.Errorf("issuer corrupted, expected %s got %s", testIssuer, ntok.Issuer)
	}
	if ntok.Subject != testSubject {
		t.Errorf("subject corrupted, expected %s got %s", testSubject, ntok.Subject)
	}
	if ntok.Get("name") != testName {
		t.Errorf("name corrupted, expected %s got %s", testName, ntok.Get("name"))
	}
	if ntok.Get("email") != testEmail {
		t.Errorf("email corrupted, expected %s got %s", testEmail, ntok.Get("email"))
	}

}

func TestSessionKeys(t *testing.T) {
	s1 := pasetosession.NewSessionManager("passphrase #1", 1*time.Minute)
	s2 := pasetosession.NewSessionManager("passphrase #2", 1*time.Minute)
	tok1, err := s1.EncodeToken("testsubject@example.com")
	if err != nil {
		t.Errorf("failed to encode subject-only token")
	}
	tok2, err := s2.DecodeToken(tok1, false)
	if err == nil {
		t.Errorf("tokens were passed between session managers with different secret keys")
	}
	if tok2 != nil && tok2.Subject != "" {
		t.Errorf("unexpected token subject output from erroneous decode: %s", tok2.Subject)
	}
}

func TestSessionTimeout(t *testing.T) {
	s := pasetosession.NewSessionManager("passphrase #1", 1*time.Second)
	tok1, err := s.EncodeToken("testsubject@example.com")
	if err != nil {
		t.Errorf("failed to encode subject-only token")
	}
	tok2, err := s.EncodeToken("testsubject@example.com")
	if err != nil {
		t.Errorf("failed to encode subject-only token")
	}
	toko, err := s.DecodeToken(tok1, false)
	if err != nil {
		t.Fatalf("failed to decode subject-only token inside expiry limit")
	}
	if toko.Subject != "testsubject@example.com" {
		t.Errorf("token timeout test decode fail")
	}
	time.Sleep(2 * time.Second)
	toko, err = s.DecodeToken(tok2, false)
	if err == nil {
		t.Errorf("managed to decode subject-only token outside expiry limit")
	}
}

// Get a test cookie, then run it through refresh
func TestCookieIssueAndRefresh(t *testing.T) {
	c := getTestCookie(t)

	req, err := http.NewRequest("GET", "/baz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c)

	w := httptest.NewRecorder()
	hndl := sessMgr.Refresh(okHandler(t, true))
	hndl.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected http response using cookie: %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, testCookieName)
	if err != nil {
		t.Fatalf("no refreshed cookie issued")
	}
	if ctok.Value == c.Value {
		t.Error("same cookie issued on refresh")
	}
	verifyTestCookie(t, ctok)
}

func TestAuthSuccess(t *testing.T) {
	c := getTestCookie(t)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c)

	w := httptest.NewRecorder()
	hndl := sessMgr.Authenticate(okHandler(t, true))
	hndl.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected auth rejection using valid cookie: %d", resp.StatusCode)
	}
}

func TestAuthFail(t *testing.T) {
	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	hndl := sessMgr.Authenticate(okHandler(t, false))
	hndl.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("unexpected auth success using no cookie: %d", resp.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	c := getTestCookie(t)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c)

	w := httptest.NewRecorder()
	// Context should be found while we're processing the logout, it just kills the cookie afterwards
	hndl := sessMgr.Logout(okHandler(t, false))
	hndl.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected auth rejection using valid cookie: %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, testCookieName)
	if err != nil {
		t.Fatalf("failed to get cookie: %v", err)
	}
	if ctok.Value != "" {
		t.Error("logout failed, cookie survived")
	}
}

// Run a test request through the test cookie issuing handler,
// return a debug cookie.
func getTestCookie(t *testing.T) *http.Cookie {
	req, err := http.NewRequest("GET", "/foo/bar", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	hndl := http.HandlerFunc(testCookieIssuer)
	hndl.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected http response issuing cookie: %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, testCookieName)
	if err != nil {
		t.Error("no cookie issued")
	}
	verifyTestCookie(t, ctok)
	return ctok
}

func getCookie(r *http.Response, name string) (*http.Cookie, error) {
	cookies := r.Cookies()
	for _, c := range cookies {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no cookie %s found", name)
}

func testCookieIssuer(w http.ResponseWriter, r *http.Request) {
	sessMgr.TokenToCookie(w, testSubject)
	fmt.Fprintln(w, "OK")
}

func okHandler(t *testing.T, requirecontext bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Msgf("checking for context on request %+v", r)
		tok, ok := pasetosession.GetToken(r)
		if requirecontext != ok {
			t.Errorf("context presence mismatch, expected=%v, found=%v", requirecontext, ok)
		} else {
			log.Debug().Msgf("context = %+v", tok)
		}
		fmt.Fprintln(w, "OK")
	}
}

func verifyTestCookie(t *testing.T, ctok *http.Cookie) {
	if ctok.Path != "/" {
		t.Errorf("Wrong cookie path, expected / got %s", ctok.Path)
	}
	exp := ctok.Expires
	expexp := time.Now().Add(testLifespan)
	durd := expexp.Sub(exp)
	if durd > time.Second {
		t.Errorf("Cookie lifetime incorrect, expected %v got %v", expexp.UTC(), exp.UTC())
	}
	if !ctok.HttpOnly {
		t.Error("Cookie not marked as HttpOnly (XSS vulnerability)")
	}
	log.Debug().Msg("cookie verified")
}
