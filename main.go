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
	}
	hashes map[string]time.Time
}

func main() {
	app := new(application)

	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")
	app.auth.realm = getenv("AUTH_REALM", "ForwardBasic")
	app.hashes = make(map[string]time.Time)

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided (bcrypt hashed)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.unprotectedHandler)
	mux.HandleFunc("/authorize", app.basicAuth(app.protectedHandler))

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

func (app *application) protectedHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintln(w, "OK")
}

func (app *application) generateCookie(w http.ResponseWriter) {
	expiration := time.Now().Add(24 * time.Hour)
	cookieId := uuid.New().String()

	app.hashes[cookieId] = expiration
	cookie := http.Cookie{Name: "forwardauth_id", Value: cookieId, Expires: expiration}
	http.SetCookie(w, &cookie)
}

func (app *application) unprotectedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "KO", http.StatusNotFound)
}

func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("forwardauth_id")
		if cookie != nil {
			if expiration, ok := app.hashes[cookie.Value]; ok {
				if time.Now().Before(expiration) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		username, password, ok := r.BasicAuth()
		if ok {
			usernameMatch := strings.Compare(username, app.auth.username) == 0
			passwordMatch := app.matchPassword(password)

			if usernameMatch && passwordMatch {
				log.Printf("Authenticated: %s", username)
				app.generateCookie(w)
				next.ServeHTTP(w, r)
				return
			} else if username != "" {
				log.Printf("Access denied: %s", username)
			}
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, app.auth.realm))
		http.Error(w, "KO", http.StatusUnauthorized)
	})
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
