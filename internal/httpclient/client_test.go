package httpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeaderInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "1" {
			t.Fatalf("expected header injected")
		}
		if r.Header.Get("Cookie") != "token=abc" {
			t.Fatalf("expected cookie injected")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := Config{
		Timeout: 1 * time.Second,
		Headers: http.Header{"X-Test": []string{"1"}},
		Cookie:  "token=abc",
	}
	client := New(cfg)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
}

func TestRetry(t *testing.T) {
	t.Run("5xx", func(t *testing.T) {
		attempts := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(200)
		}))
		defer srv.Close()

		client := New(Config{Timeout: 1 * time.Second, Retries: 2})
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected final 200, got %d", resp.StatusCode)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
		resp.Body.Close()
	})

	t.Run("network error", func(t *testing.T) {
		attempts := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts == 1 {
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			w.WriteHeader(200)
		}))
		defer srv.Close()

		client := New(Config{Timeout: 1 * time.Second, Retries: 1})
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if attempts != 2 {
			t.Fatalf("expected 2 attempts, got %d", attempts)
		}
		resp.Body.Close()
	})
}
