package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
	"log"
	rand2 "math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

type application struct {
	auth struct {
		username string
		password string
		realm    string
		cookie   string
	}
	sc          *securecookie.SecureCookie
	allowOption bool
	debug       bool
}

func main() {
	app := new(application)

	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")
	app.auth.realm = getenv("AUTH_REALM", "ForwardBasic")
	app.auth.cookie = getenv("AUTH_COOKIE", "forward_auth_id")
	app.allowOption = os.Getenv("ALLOW_OPTION_REQ") == "yes"
	app.debug = os.Getenv("DEBUG") == "yes"

	hashKeyString := getenv("AUTH_HASH_KEY", hex.EncodeToString(randomBytes(32)))

	hashKey, err := hex.DecodeString(hashKeyString)
	if err != nil {
		log.Fatalf("Unable to decode AUTH_HASH_KEY: %s", err)
	}

	if len(hashKey) != 32 {
		log.Fatal("Unable to decode AUTH_HASH_KEY! Invalid HEX string")
	}

	app.sc = securecookie.New(hashKey, nil)

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided (bcrypt hashed)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", app.authenticateRequest)

	log.Printf("Realm: %s", app.auth.realm)
	log.Printf("Cookie: %s", app.auth.cookie)
	log.Printf("Username: %s", app.auth.username)
	log.Printf("Allow Options: %t", app.allowOption)
	log.Printf("Debug: %t", app.debug)

	srv := &http.Server{
		Addr:         ":4000",
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("starting server on http://127.0.0.1:4000/authorize")
	err = srv.ListenAndServe()
	log.Fatal(err)
}

func (app *application) generateCookie(w http.ResponseWriter) {
	expiration := time.Now().Add(24 * time.Hour)
	value := map[string]string{
		"expiration": expiration.Format(time.RFC3339),
	}

	if encoded, err := app.sc.Encode(app.auth.cookie, value); err == nil {
		cookie := &http.Cookie{
			Name:    app.auth.cookie,
			Value:   encoded,
			Path:    "/",
			Expires: expiration,
		}

		http.SetCookie(w, cookie)
	}
}

func (app *application) Debug(format string, v ...interface{}) {
	if app.debug {
		log.Printf(format, v...)
	}
}

func (app *application) authenticateRequest(w http.ResponseWriter, r *http.Request) {

	if app.allowOption && r.Method == http.MethodOptions {
		app.Debug("Request authorized (OPTIONS allowed by config). %v", r.Header)

		_, _ = fmt.Fprintln(w, "OK")
		return
	}

	if cookie, err := r.Cookie(app.auth.cookie); err == nil {
		value := make(map[string]string)
		if err = app.sc.Decode(app.auth.cookie, cookie.Value, &value); err == nil {
			eStr := value["expiration"]
			expiration, _ := time.Parse(time.RFC3339, eStr)

			if time.Now().Before(expiration) {
				app.Debug("Request authorized (cookie validated). %v", r.Header)
				_, _ = fmt.Fprintln(w, "OK")
				return
			} else {
				app.Debug("Request DENIED (cookie outdated!). %v", r.Header)
			}
		} else {
			app.Debug("Request DENIED (cookie invalid!). %v", r.Header)
		}
	}

	username, password, ok := r.BasicAuth()
	if ok {
		usernameMatch := strings.Compare(username, app.auth.username) == 0
		passwordMatch := app.matchPassword(password)

		if usernameMatch && passwordMatch {
			host := r.Header.Get("X-Forwarded-Host")
			port := r.Header.Get("X-Forwarded-Port")
			scheme := r.Header.Get("X-Forwarded-Proto")
			sourceIp := r.Header.Get("X-Forwarded-For")
			path := r.Header.Get("X-Forwarded-Uri")

			redirect := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, path)

			log.Printf("Authenticated: %s (IP: %s, redirect: %s). %v", username, sourceIp, redirect, r.Header)

			app.generateCookie(w)
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		} else if username != "" {
			log.Printf("Access denied: %s. %v", username, r.Header)
		}
	}

	app.Debug("Request DENIED %v", r.Header)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, app.auth.realm))
	http.Error(w, "KO", http.StatusUnauthorized)
}

func (app *application) matchPassword(plainTextPassword string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(app.auth.password),
		[]byte(plainTextPassword))

	if err != nil {
		return false
	}
	return true
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func randomBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Unable to generate secure string: %s", err)

		rand2.Read(b)
		return b
	}

	return b
}
