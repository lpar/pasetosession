package main

// This is a trivial demo of using paseotosessions.

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lpar/blammo/log"
	"github.com/lpar/paseto"
	"github.com/lpar/pasetosession"
)

// Example values for this demo
const exampleLogin = "john"
const examplePassword = "gandalf"
const exampleName = "John Smith"
const exampleEmail = "jsmith@example.com"
const exampleIdleLogout = 1 * time.Minute

const myPort = ":8080"

const exampleKeyString = "Some random string of characters"

var sessmgr = pasetosession.NewSessionManager(exampleKeyString, exampleIdleLogout)

// Output a complete web page with the supplied content in the body.
func outputPage(w http.ResponseWriter, content ...string) {
	fmt.Fprintln(w, `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>`)
	for _, x := range content {
		fmt.Fprintln(w, x)
	}
	fmt.Fprintln(w, `<p>[ <a href="/">Home</a> | <a href="/login">Log in</a> | <a href="/logout">Log out</a> | <a href="/protected">Protected page</a> ]</p>
  </body>
</html>`)
}

// If the request is a GET, we display a login form.
// If it's a POST, we process the login.
// For a real web login system, remember to:
//  1. Make sure the connection is HTTPS with a valid signed certificate.
//  2. Add a CSRF cookie and check it.
//  3. Use passwords hashed via (say) bcrypt.
func loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		outputPage(w,
			`<form action="/login" method="post">
       <p><label for="login">Login</label><br>
       <input type="text" name="login" required></p>
       <p><label for="password">Password</label><br>
       <input type="password" name="password" required></p>
       <p><button type="submit">Login</button></p>
       </form>`)
		return
	}
	r.ParseForm()
	login := strings.TrimSpace(r.Form["login"][0])
	password := strings.TrimSpace(r.Form["password"][0])
	if login == exampleLogin && password == examplePassword {
		log.Debug().Msg("correct login and password, issuing token")
		tok := &paseto.JSONToken{}
		tok.Subject = login
		tok.Set("name", exampleName)
		tok.Set("email", exampleEmail)
		sessmgr.TokenToCookie(w, tok.Subject, tok)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Error(w, "No such user", http.StatusUnauthorized)
}

// Display a simple logout message.
func logoutPage(w http.ResponseWriter, r *http.Request) {
	outputPage(w, "<p>You are now logged out.</p>")
}

// Display the secret page.
func secretPage(w http.ResponseWriter, r *http.Request) {
	outputPage(w, "<p>Welcome to the secret page for authenticated users only.</p>")
}

// Output the top level page, with the user's name if logged in.
func indexPage(w http.ResponseWriter, r *http.Request) {
	tok, ok := sessmgr.GetToken(r)
	greeting := "Hello anonymous stranger."
	if ok {
		greeting = fmt.Sprintf("Hello %s <%s>.", tok.Get("name"), tok.Get("email"))
	}
	outputPage(w, "<p>", greeting, "</p>")
}

func main() {
	http.Handle("/", sessmgr.Refresh(http.HandlerFunc(indexPage)))
	http.Handle("/login", http.HandlerFunc(loginPage))
	http.Handle("/logout", sessmgr.Logout(http.HandlerFunc(logoutPage)))
	http.Handle("/protected", sessmgr.Authenticate(http.HandlerFunc(secretPage)))
	http.ListenAndServe(myPort, nil)
}
