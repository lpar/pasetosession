package pasetosession_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lpar/blammo/log"
	"github.com/lpar/pasetosession"
	"github.com/o1egl/paseto"
	flag "github.com/spf13/pflag"
)

const testIssuer = "testIssuer"
const testAudience = "testAudience"
const testSubject = "login@example.com"
const testEmail = "john.smith@example.com"
const testName = "John Q. Smith Esq."
const testCookieName = "TestSesionCookie"
const testLifespan = time.Minute

var debug = flag.Bool("debug", false, "turn on debug logging")

var sessMgr = pasetosession.NewSessionManager("chunkybacon", testLifespan)

func TestMain(m *testing.M) {
	sessMgr.Issuer = testIssuer
	sessMgr.Audience = testAudience
	sessMgr.CookieName = testCookieName

	ds := os.Getenv("DEBUG")
	if ds == "true" || ds == "1" {
		log.SetDebug(true)
	}
	os.Exit(m.Run())
}

func TestToken(t *testing.T) {
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
	ntok, err := s.DecodeToken(strtok)
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
	_, err = s.DecodeToken(strtok)
	if err == nil {
		t.Errorf("duplicate token decode allowed")
	} else {
		log.Debug().Err(err).Msg("duplicate decode attempted")
	}
}

func TestSessionKeys(t *testing.T) {
	s1 := pasetosession.NewSessionManager("passphrase #1", 1*time.Minute)
	s2 := pasetosession.NewSessionManager("passphrase #2", 1*time.Minute)
	tok1, err := s1.EncodeToken("testsubject@example.com")
	if err != nil {
		t.Errorf("failed to encode subject-only token")
	}
	tok2, err := s2.DecodeToken(tok1)
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
	toko, err := s.DecodeToken(tok1)
	if err != nil {
		t.Errorf("failed to decode subject-only token inside expiry limit")
	}
	if toko.Subject != "testsubject@example.com" {
		t.Errorf("token timeout test decode fail")
	}
	time.Sleep(2 * time.Second)
	toko, err = s.DecodeToken(tok2)
	if err == nil {
		t.Errorf("managed to decode subject-only token outside expiry limit")
	}
}

/*
type RecordingHandler struct {
  Called bool
  Token  *paseto.JSONToken
}

var recordingHandler = RecordingHandler{}

func (h RecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  // Not h, we need to store the values in the global
  recordingHandler.Called = true
  tok, ok := sessMgr.GetToken(r)
  if ok {
    recordingHandler.Token = tok
  }
}
*/

// Get a test cookie, then run it through refresh
func TestCookieIssueAndRefresh(t *testing.T) {
	c := getTestCookie(t)

	req, err := http.NewRequest("GET", "/baz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c)

	w := httptest.NewRecorder()
	hndl := sessMgr.Refresh(http.HandlerFunc(okHandler))
	hndl.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected http response using cookie: %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, testCookieName)
	if err != nil {
		t.Error("no refreshed cookie issued")
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
	hndl := sessMgr.Authenticate(http.HandlerFunc(okHandler))
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
	hndl := sessMgr.Authenticate(http.HandlerFunc(okHandler))
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
	hndl := sessMgr.Logout(http.HandlerFunc(okHandler))
	hndl.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected auth rejection using valid cookie: %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, testCookieName)
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

func okHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
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
