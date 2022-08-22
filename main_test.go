package main

import (
	"encoding/hex"
	"github.com/gorilla/securecookie"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticationRoutine(t *testing.T) {
	app := createTestApplication()

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.Header.Set("Authorization", "Basic YWxpY2U6cGFzc3dvcmQ=")
	req.Header.Set("X-Forwarded-Host", "test.golang")
	req.Header.Set("X-Forwarded-Port", "443")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Uri", "/dashboard")
	w := httptest.NewRecorder()

	app.authenticateRequest(w, req)

	res := w.Result()
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	actual := string(data)
	expect := "<a href=\"https://test.golang:443/dashboard\">Temporary Redirect</a>.\n\n"
	if actual != expect {
		t.Errorf("expected %s got %s", expect, string(data))
	}

	statusCode := w.Code
	if statusCode != http.StatusTemporaryRedirect {
		t.Errorf("expected %d got %d", http.StatusTemporaryRedirect, statusCode)
	}

	c := parseCookie(w, "test-cookie")
	if c == nil {
		t.Errorf("Expected cookie, got NIL")
	}
	if c.Name != "test-cookie" {
		t.Errorf("Expected cookie \"test-cookie\"', got %s", c.Name)
	}
	if c.Value == "" {
		t.Errorf("Expected cookie, got ''")
	}

	// Part 2, Test that cookie is authenticated!

	req = httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.AddCookie(c)
	req.Header.Set("Authorization", "Basic YWxpY2U6cGFzc3dvcmQ=")
	req.Header.Set("X-Forwarded-Host", "test.golang")
	req.Header.Set("X-Forwarded-Port", "443")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Uri", "/dashboard")
	w = httptest.NewRecorder()

	app.authenticateRequest(w, req)

	res = w.Result()
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()
	data, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	statusCode = w.Code
	if statusCode != http.StatusOK {
		t.Errorf("expected %d got %d", http.StatusOK, statusCode)
	}

	actual = string(data)
	expect = "OK\n"
	if actual != expect {
		t.Errorf("expected %s got %s", expect, string(data))
	}
}

func TestAccessDenied(t *testing.T) {
	app := createTestApplication()

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.Header.Set("X-Forwarded-Host", "test.golang")
	req.Header.Set("X-Forwarded-Port", "443")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Uri", "/dashboard")
	w := httptest.NewRecorder()

	app.authenticateRequest(w, req)

	res := w.Result()
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	actual := string(data)
	expect := "KO\n"
	if actual != expect {
		t.Errorf("expected %s got %s", expect, string(data))
	}

	statusCode := w.Code
	if statusCode != http.StatusUnauthorized {
		t.Errorf("expected %d got %d", http.StatusUnauthorized, statusCode)
	}
}

func createTestApplication() application {
	decodeString, _ := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	return application{
		auth: struct {
			username string
			password string
			realm    string
			cookie   string
		}{
			username: "alice",
			password: "$2y$10$VhbeCHM9IsG/9n9JU/cN/ufketp3fOhcPCfBxjHKrTYdc4iZRKQ0i",
			realm:    "TEST",
			cookie:   "test-cookie",
		},
		sc:               securecookie.New(decodeString, nil),
		debug:            true,
		allowOption:      true,
		cookieExpiration: 24 * time.Hour,
		cookieDomain:     "test.golang",
	}
}

func parseCookie(recorder *httptest.ResponseRecorder, cookieName string) *http.Cookie {
	// Copy the Cookie over to a new Request
	get := recorder.Header().Values("Set-Cookie")
	request := &http.Request{Header: http.Header{"Cookie": get}}

	// Extract the dropped cookie from the request.
	cookie, _ := request.Cookie(cookieName)
	return cookie
}
