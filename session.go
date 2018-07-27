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

	"github.com/lpar/blammo/log"
	"github.com/lpar/paseto"
	"github.com/lpar/serial"
)

const defaultCookieName = "Session"

type contextKey string

var defaultContextName = contextKey("session")

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
	// The Go context key to use when placing the token into the http Context.
	// If you don't know what that means it's safe to ignore it.
	ContextName contextKey
	// The URL to redirect users to when they attempt to access a page
	// protected by the Authenticate wrapper and they aren't authenticated.
	// If no URL is specified, they just get a 401 error.
	LoginURL      string
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
		ContextName:   defaultContextName,
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
				log.Debug().Msg("running GC on used jti cache")
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
	token, err = s.pasetov2.Encrypt(s.symmetricKey, json)
	return token, err
}

// DecodeToken takes a string containing an encoded token, decodes it, and
// verifies its validity by checking the audience, issuer, expiry timestamp,
// and not-before timestamp, and making sure the token hasn't previously been decoded.
func (s *SessionManager) DecodeToken(tok string) (*paseto.JSONToken, error) {
	var token paseto.JSONToken
	err := s.pasetov2.Decrypt(tok, s.symmetricKey, &token, nil)
	if err == nil {
		// Run validations in approximate order of difficulty, quickest first
		err = token.Validate(
			paseto.ForAudience(s.Audience),
			paseto.IssuedBy(s.Issuer),
			paseto.ValidAt(time.Now()),
			ValidSequence(s.serialGen),
		)
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
}

func (s *SessionManager) cookieToToken(r *http.Request) (*paseto.JSONToken, error) {
	var tok *paseto.JSONToken
	ctok, err := r.Cookie(s.CookieName)
	if err != nil {
		return tok, err
	}
	tok, err = s.DecodeToken(ctok.Value)
	return tok, err
}

func (s *SessionManager) tokenToContext(tok *paseto.JSONToken, r *http.Request) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, s.ContextName, tok)
	r = r.WithContext(ctx)
	return r
}

// GetToken extracts the paseto.JSONToken from the http.Request's Context, and return it.
// The ok return value indicates whether any such context value was found.
// This is the method to call to access the session information in your web app's handlers.
func (s *SessionManager) GetToken(r *http.Request) (*paseto.JSONToken, bool) {
	ctx := r.Context()
	var tok *paseto.JSONToken
	var ok bool
	if ctx != nil {
		tok, ok = ctx.Value(s.ContextName).(*paseto.JSONToken)
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
		tok, err := s.cookieToToken(r)
		if err == nil {
			log.Debug().Msg("reissuing valid session token")
			s.TokenToCookie(w, tok.Subject, tok)
			r = s.tokenToContext(tok, r)
		} else {
			if s.LoginURL != "" {
				log.Debug().Str("url", s.LoginURL).Msg("issuing redirect to login URL")
				http.Redirect(w, r, s.LoginURL, http.StatusSeeOther)
				return
			}
			log.Debug().Msg("issuing 401 as no login URL known")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		xhnd.ServeHTTP(w, r)
	})
}

// Refresh decodes and refreshes any session token cookie, and places any decoded
// token in the HTTP context before calling the wrapped handler.
func (s *SessionManager) Refresh(xhnd http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Refresh here
		tok, err := s.cookieToToken(r)
		if err == nil {
			log.Debug().Msg("reissuing valid session token")
			s.TokenToCookie(w, tok.Subject, tok)
			r = s.tokenToContext(tok, r)
		} else {
			log.Debug().Msg("ignoring invalid session token")
		}
		xhnd.ServeHTTP(w, r)
	})
}

// Logout deletes the session cookie then calls the wrapped handler.
func (s *SessionManager) Logout(xhnd http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.deleteCookie(w, r)
		xhnd.ServeHTTP(w, r)
	})
}
