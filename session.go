// Package pasetosession builds on PASETO to provide session handling functions
// for web applications.
package pasetosession

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lpar/serial"
	"github.com/o1egl/paseto"
)

const defaultCookieName = "Session"
const defaultSameSite = "lax"

type contextKey string

// ContextName is the default context key to use when storing the user information in the Request context.
var ContextName = contextKey("session")

const jtiBase = 36

// SessionManager handles web sessions using PASETO tokens.
// It provides utility handler wrappers and methods to issue
// tokens, refresh them, require them, and so on.
type SessionManager struct {
	// The Issuer string to use in your tokens. Blank for no issuer (default).
	Issuer string
	// The Audience string to use in your tokens. Blank for no audience (default).
	Audience string
	// The Cookie name to use for session cookies. Default is "Session".
	CookieName string
	// The URL to redirect users to when they attempt to access a page
	// protected by the Authenticate wrapper and they aren't authenticated.
	// If no URL is specified, they just get a 401 error.
	LoginURL string
	// The value of the SameSite attribute to use for the issued cookie.
	// Default is "lax". See https://tools.ietf.org/html/draft-west-first-party-cookies-07
	SameSite      string
	serialGen     *serial.Generator
	gc            chan struct{}
	symmetricKey  []byte
	pasetov2      paseto.Protocol
	tokenLifetime time.Duration
	sequences     map[string]int
}

// NewSessionManager creates a new SessionManager object you can use to issue and
// check web sessions.
// The keySeed is any random string, and is used to generate the secret key for
// session security. It is passed through SHA2-256 before use.
// The tokenLifetime defines how long any given session cookie will remain valid.
func NewSessionManager(keySeed string, tokenLifetime time.Duration) *SessionManager {
	sk := sha256.Sum256([]byte(keySeed))
	s := &SessionManager{
		pasetov2:      paseto.NewV2(),
		symmetricKey:  sk[:],
		tokenLifetime: tokenLifetime,
		CookieName:    defaultCookieName,
		SameSite:      defaultSameSite,
		serialGen:     serial.NewGenerator(),
	}
	s.StartGC()
	return s
}

// StartGC begins the JTI cache garbage collector.
func (s *SessionManager) StartGC() chan struct{} {
	ticker := time.NewTicker(s.tokenLifetime / 2)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				s.serialGen.ExpireSeen(s.tokenLifetime)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	return quit
}

// StopGC stops the JTI cache garbage collector.
func (s *SessionManager) StopGC() {
	close(s.gc)
}

// ValidSequence is a paseto.Validator which checks that a token
// has not already been used, by checking the sequence number in
// the jti field.
func ValidSequence(sergen *serial.Generator) paseto.Validator {
	return func(token *paseto.JSONToken) error {
		if token.Jti == "" {
			return errors.New("missing jti in token")
		}
		jti, err := strconv.ParseInt(token.Jti, jtiBase, 64)
		if err != nil {
			return errors.New("bad jti in token")
		}
		if sergen.Seen(serial.Serial(jti)) {
			return errors.New("token reuse detected")
		}
		sergen.SetSeen(serial.Serial(jti))
		return nil
	}
}

// EncodeToken converts a paseto.JSONToken to a String suitable for storing in a session cookie,
// placing in client-side storage, handing to a REST client, or whatever.
func (s *SessionManager) EncodeToken(subject string, jsontok ...*paseto.JSONToken) (string, error) {
	token := ""
	var json paseto.JSONToken
	if len(jsontok) > 0 {
		json = *jsontok[0]
	}
	if len(jsontok) > 1 {
		return token, errors.New("bad MakeToken call: too many arguments")
	}
	now := time.Now()
	exp := now.Add(s.tokenLifetime)
	nbt := now
	jti := s.serialGen.Generate()
	jtis := strconv.FormatInt(int64(jti), jtiBase)
	json.Subject = subject
	if s.Audience != "" {
		json.Audience = s.Audience
	}
	if s.Issuer != "" {
		json.Issuer = s.Issuer
	}
	json.Jti = jtis
	json.NotBefore = nbt
	json.IssuedAt = now
	json.Expiration = exp
	var err error
	token, err = s.pasetov2.Encrypt(s.symmetricKey, json, nil)
	return token, err
}

// DecodeToken takes a string containing an encoded token, decodes it, and
// verifies its validity by checking the audience, issuer, expiry timestamp,
// and not-before timestamp, and making sure the token hasn't previously been decoded.
// If allowReuse is set, the final validation step is skipped and the token isn't marked as used.
func (s *SessionManager) DecodeToken(tok string, allowReuse bool) (*paseto.JSONToken, error) {
	var token paseto.JSONToken
	err := s.pasetov2.Decrypt(tok, s.symmetricKey, &token, nil)
	if err == nil {
		if allowReuse {
			err = token.Validate(
				paseto.ForAudience(s.Audience),
				paseto.IssuedBy(s.Issuer),
				paseto.ValidAt(time.Now()),
			)
		} else {
			// Run validations in approximate order of difficulty, quickest first
			err = token.Validate(
				paseto.ForAudience(s.Audience),
				paseto.IssuedBy(s.Issuer),
				paseto.ValidAt(time.Now()),
				ValidSequence(s.serialGen),
			)
		}
	}
	return &token, err
}

func (s *SessionManager) deleteCookie(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     s.CookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)
}

// TokenToCookie issues a token as a browser cookie. The subject is the subject value for the
// issued token (generally the primary user ID of the authenticated user). The optional
// paseto.JSONToken contains any additional data you wish to include in the token.
func (s *SessionManager) TokenToCookie(w http.ResponseWriter, subject string, jsontok ...*paseto.JSONToken) {
	tok, err := s.EncodeToken(subject, jsontok...)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating session: %v", err), http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(s.tokenLifetime)
	cookie := &http.Cookie{
		Name:     s.CookieName,
		Value:    tok,
		Expires:  expires,
		MaxAge:   int(s.tokenLifetime.Seconds()),
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)
	// Workaround for https://github.com/golang/go/issues/15867
	cs := w.Header().Get("Set-Cookie")
	cs += "; SameSite=" + s.SameSite
	w.Header().Set("Set-Cookie", cs)
}

func (s *SessionManager) cookieToToken(r *http.Request, allowReuse bool) (*paseto.JSONToken, error) {
	var tok *paseto.JSONToken
	ctok, err := r.Cookie(s.CookieName)
	if err != nil {
		return tok, err
	}
	tok, err = s.DecodeToken(ctok.Value, allowReuse)
	return tok, err
}

func (s *SessionManager) tokenToContext(tok *paseto.JSONToken, r *http.Request) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, ContextName, tok)
	r = r.WithContext(ctx)
	return r
}

// GetToken extracts the paseto.JSONToken from the http.Request's Context, and return it.
// The ok return value indicates whether any such context value was found.
// This is the method to call to access the session information in your web app's handlers.
func GetToken(r *http.Request) (*paseto.JSONToken, bool) {
	ctx := r.Context()
	var tok *paseto.JSONToken
	var ok bool
	if ctx != nil {
		tok, ok = ctx.Value(ContextName).(*paseto.JSONToken)
	}
	return tok, ok
}

// Authenticate checks the web session for a token cookie indicating an authenticated user.
// If one is found, it is decoded and the wrapped handler is called with the token in the
// http context.
// If no valid session token is found, the wrapped handler is not called.
// If the SessionManager has been provided with a LoginURL, the browser is redirected
// to that URL to log in. Otherwise, a 401 unauthorized error is issued.
func (s *SessionManager) Authenticate(xhnd http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, ok := s.processAuthCookie(w, r, false)
		if ok {
			xhnd.ServeHTTP(w, r)
		}
	})
}

// AuthenticateFunc is like Authenticate, except it takes a HandlerFunc as argument
// and returns a HandlerFunc as well.
func (s *SessionManager) AuthenticateFunc(hndfunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r, ok := s.processAuthCookie(w, r, false)
		if ok {
			hndfunc(w, r)
		}
	}
}

// AuthenticateAjax is like Authenticate, except that tokens are not "spent" and can be
// reused in other AuthenticateAjax calls until they expire.
// The purpose is to allow authenticated protection of an AJAX endpoint, since
// JavaScript POST events won't cause the browser's cookie store to be updated with any
// new cookie issued.
func (s *SessionManager) AuthenticateAjax(xhnd http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, ok := s.processAuthCookie(w, r, true)
		if ok {
			xhnd.ServeHTTP(w, r)
		}
	})
}

// AuthenticateFunc is like Authenticate, except it takes a HandlerFunc as argument
// and returns a HandlerFunc as well.
func (s *SessionManager) AuthenticateFuncAjax(hndfunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r, ok := s.processAuthCookie(w, r, true)
		if ok {
			hndfunc(w, r)
		}
	}
}

// returns true if valid cookie/token was found, false otherwise
func (s *SessionManager) processAuthCookie(w http.ResponseWriter, r *http.Request, allowReuse bool) (*http.Request, bool) {
	tok, err := s.cookieToToken(r, allowReuse)
	if err == nil {
		if !allowReuse {
			s.TokenToCookie(w, tok.Subject, tok)
		}
		r = s.tokenToContext(tok, r)
		return r, true
	} else {
		if s.LoginURL != "" {
			http.Redirect(w, r, s.LoginURL, http.StatusSeeOther)
			return r, false
		}
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return r, false
	}
}

// Refresh decodes and refreshes any session token cookie, and places any decoded
// token in the HTTP context before calling the wrapped handler.
func (s *SessionManager) Refresh(xhnd http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.refreshAuthCookie(w, r)
		xhnd.ServeHTTP(w, r)
	})
}

// RefreshFunc is the HandlerFunc version of Refresh.
func (s *SessionManager) RefreshFunc(hndfnc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = s.refreshAuthCookie(w, r)
		hndfnc(w, r)
	}
}

func (s *SessionManager) refreshAuthCookie(w http.ResponseWriter, r *http.Request) *http.Request {
	tok, err := s.cookieToToken(r, false)
	if err == nil {
		s.TokenToCookie(w, tok.Subject, tok)
		r = s.tokenToContext(tok, r)
	}
	return r
}

// Logout deletes the session cookie then calls the wrapped Handler.
func (s *SessionManager) Logout(xhnd http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.deleteCookie(w, r)
		xhnd.ServeHTTP(w, r)
	})
}

// Logout deletes the session cookie then calls the wrapped HandlerFunc.
func (s *SessionManager) LogoutFunc(hndfnc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.deleteCookie(w, r)
		hndfnc(w, r)
	}
}
