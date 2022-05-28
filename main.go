package main

import (
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
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
	hashes map[string]time.Time
}

func main() {
	app := new(application)

	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")
	app.auth.realm = getenv("AUTH_REALM", "ForwardBasic")
	app.auth.cookie = getenv("AUTH_COOKIE", "forward_auth_id")
	app.hashes = make(map[string]time.Time)

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided (bcrypt hashed)")
	}

	mux := http.NewServeMux()
	//mux.HandleFunc("/", app.unprotectedHandler)
	mux.HandleFunc("/authorize", app.authenticateRequest)

	srv := &http.Server{
		Addr:         ":4000",
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("starting server on http://127.0.0.1:4000/authorize")
	err := srv.ListenAndServe()
	log.Fatal(err)
}

func (app *application) generateCookie(w http.ResponseWriter) {
	expiration := time.Now().Add(24 * time.Hour)
	cookieId := uuid.New().String()

	app.hashes[cookieId] = expiration
	cookie := http.Cookie{Name: app.auth.cookie, Value: cookieId, Expires: expiration}
	http.SetCookie(w, &cookie)
}

func (app *application) unprotectedHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "KO", http.StatusNotFound)
}

func (app *application) authenticateRequest(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(app.auth.cookie)
	if cookie != nil {
		if expiration, ok := app.hashes[cookie.Value]; ok {
			if time.Now().Before(expiration) {
				_, _ = fmt.Fprintln(w, "OK")
				return
			}
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

			log.Printf("Authenticated: %s (IP: %s, redirect: %s)", username, sourceIp, redirect)

			app.generateCookie(w)
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		} else if username != "" {
			log.Printf("Access denied: %s", username)
		}
	}

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
