package trace_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"redirecthunter/internal/httpclient"
	"redirecthunter/internal/trace"
)

func setupServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/302", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<meta http-equiv=\"refresh\" content=\"0;url=/final\">"))
	})
	mux.HandleFunc("/js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<script>window.location='/final'</script>"))
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	mux.HandleFunc("/internal", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1/", http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return httptest.NewServer(mux)
}

func TestTraceBasic(t *testing.T) {
	srv := setupServer()
	defer srv.Close()

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second})
	tr := trace.New(client)

	res := tr.Trace(context.Background(), srv.URL+"/302", 5, false)
	if len(res.Chain) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(res.Chain))
	}
	if res.Chain[1].Status != 200 {
		t.Fatalf("expected final 200")
	}
}

func TestMetaAndJS(t *testing.T) {
	srv := setupServer()
	defer srv.Close()
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second})
	tr := trace.New(client)

	r1 := tr.Trace(context.Background(), srv.URL+"/meta", 5, true)
	if len(r1.Chain) < 2 || r1.Chain[1].Via != "meta-refresh" {
		t.Fatalf("meta refresh not detected")
	}
	r2 := tr.Trace(context.Background(), srv.URL+"/js", 5, true)
	if len(r2.Chain) < 2 || r2.Chain[1].Via != "js" {
		t.Fatalf("js redirect not detected")
	}
}

func TestDetections(t *testing.T) {
	srv := setupServer()
	defer srv.Close()
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second})
	tr := trace.New(client)

	// SSRF
	ssrf := tr.Trace(context.Background(), srv.URL+"/internal", 5, false)
	if len(ssrf.Findings) == 0 || ssrf.Findings[0].Type != "SSRF" {
		t.Fatalf("expected SSRF finding")
	}

	// Token leak
	token := tr.Trace(context.Background(), srv.URL+"/token?access_token=abc", 5, false)
	found := false
	for _, f := range token.Findings {
		if f.Type == "TOKEN_LEAK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected token leak finding")
	}

	// Loop
	loop := tr.Trace(context.Background(), srv.URL+"/loop", 3, false)
	found = false
	for _, f := range loop.Findings {
		if f.Type == "CHAIN_LOOP" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected loop detection")
	}

	// HTTPS downgrade
	httpsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/final", http.StatusFound)
	}))
	defer httpsSrv.Close()
	insecureClient := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, Insecure: true})
	tr2 := trace.New(insecureClient)
	down := tr2.Trace(context.Background(), httpsSrv.URL, 5, false)
	found = false
	for _, f := range down.Findings {
		if f.Type == "HTTPS_DOWNGRADE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected https downgrade finding")
	}
}
