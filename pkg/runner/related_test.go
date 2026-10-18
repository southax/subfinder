package runner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
)

// relatedServer answers /v1/related/ with two pages for the seed "seed.example".
func relatedServer(t *testing.T, hits *atomic.Int64, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		if req.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"code":"unauthorized","message":"bad key"}}`)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"code":"quota_exceeded","message":"out"}}`)
			return
		}
		if req.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, `{"meta":{"next_cursor":"c2","units_charged":3,"units_to_complete":1,"units_remaining":50},
"seed":{"signals":[{"class":"infrastructure"},{"class":"subject"},{"class":"infrastructure"}]},
"matches":[{"apex":"owned.example","class":"subject"},{"apex":"maybe.example","class":"review"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"meta":{"next_cursor":null,"units_charged":1},"matches":[{"apex":"Second.example","class":"subject"},{"apex":"maybe2.example","class":"review"}]}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRelatedLookupPagesAndClasses(t *testing.T) {
	var hits atomic.Int64
	server := relatedServer(t, &hits, 0)
	client := &relatedClient{baseURL: server.URL, key: "test-key", http: server.Client()}
	result, err := client.lookup(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || result.Pages != 2 || result.Units != 4 {
		t.Errorf("hits=%d pages=%d units=%d, want 2 2 4", hits.Load(), result.Pages, result.Units)
	}
	if got := strings.Join(result.ByClass[classSubject], ","); got != "owned.example,Second.example" {
		t.Errorf("subjects=%s", got)
	}
	if len(result.ByClass[classReview]) != 2 || result.InfrastructureSignals != 2 {
		t.Errorf("review=%v infra=%d", result.ByClass[classReview], result.InfrastructureSignals)
	}
}

func TestRelatedLookupFailsFastOnAllowance(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{"meta":{"next_cursor":"c2","units_charged":2,"units_to_complete":5,"units_remaining":1},"matches":[{"apex":"owned.example","class":"subject"}]}`)
	}))
	defer server.Close()
	client := &relatedClient{baseURL: server.URL, key: "k", http: server.Client()}
	result, err := client.lookup(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || result.Stopped == "" || len(result.ByClass[classSubject]) != 1 {
		t.Errorf("hits=%d stopped=%q by=%v", hits.Load(), result.Stopped, result.ByClass)
	}
}

func TestRelatedLookupAuthError(t *testing.T) {
	var hits atomic.Int64
	server := relatedServer(t, &hits, 0)
	client := &relatedClient{baseURL: server.URL, key: "wrong", http: server.Client()}
	_, err := client.lookup(context.Background(), "seed.example")
	apiErr, ok := err.(*relatedAPIError)
	if !ok || !apiErr.fatal() || apiErr.Code != "unauthorized" {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("error leaks the key")
	}
}

func TestParseRelatedClasses(t *testing.T) {
	if got, err := parseRelatedClasses(nil); err != nil || strings.Join(got, ",") != "subject" {
		t.Errorf("default: %v %v", got, err)
	}
	if got, err := parseRelatedClasses([]string{"subject,review"}); err != nil || len(got) != 2 {
		t.Errorf("both: %v %v", got, err)
	}
	if _, err := parseRelatedClasses([]string{"infrastructure"}); err == nil {
		t.Error("infrastructure must be refused")
	}
	if _, err := parseRelatedClasses([]string{"bogus"}); err == nil {
		t.Error("unknown class must be refused")
	}
}

// TestRunnerAddsRelatedDomains runs the whole pipeline: the added domain is
// enumerated with the same source, tagged in JSON, deduplicated against the
// user's own input, and the banner goes to the banner writer only.
func TestRunnerAddsRelatedDomains(t *testing.T) {
	var hits atomic.Int64
	server := relatedServer(t, &hits, 0)

	var banner bytes.Buffer
	previous := relatedBannerWriter
	relatedBannerWriter = &banner
	t.Cleanup(func() { relatedBannerWriter = previous })

	r := delayedRunner(t, 2, &delayedSource{delay: time.Millisecond})
	r.options.JSON = true
	r.related = &relatedSettings{key: "test-key", classes: []string{classSubject}}
	// Point the client at the test server by swapping the transport.
	oldTransport := http.DefaultTransport
	http.DefaultTransport = rewriteTransport{server.URL}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	var out bytes.Buffer
	// second.example is passed by the user too, so it must not be added twice.
	input := "seed.example\nsecond.example\n"
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(input), []io.Writer{&out}); err != nil {
		t.Fatal(err)
	}

	type line struct {
		Host, Input, NdxerSeed, NdxerClass string
	}
	got := map[string]line{}
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := jsoniter.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		l := line{}
		l.Host, _ = m["host"].(string)
		l.NdxerSeed, _ = m["ndxer_seed"].(string)
		l.NdxerClass, _ = m["ndxer_class"].(string)
		got[l.Host] = l
	}
	if l := got["www.owned.example"]; l.NdxerSeed != "seed.example" || l.NdxerClass != "subject" {
		t.Errorf("added host not tagged: %+v (all: %v)", l, got)
	}
	if l, ok := got["www.seed.example"]; !ok || l.NdxerSeed != "" {
		t.Errorf("seed host must be untagged: %+v", l)
	}
	if l, ok := got["www.second.example"]; !ok || l.NdxerSeed != "" {
		t.Errorf("user-passed domain must stay untagged: %+v", l)
	}
	if len(got) != 3 {
		t.Errorf("hosts=%v, want 3", got)
	}
	text := banner.String()
	for _, want := range []string{
		"owned.example",
		"NOT added: 2 review",
		"-ndxer-related-classes subject,review",
		"Units charged by the related lookup: 4",
		"about 1 unit per page for each added domain (1 domains)",
		"-no-ndxer-related",
		`curl -s -H "Authorization: Bearer $NDXER_API_KEY" "https://api.ndxer.com/v1/related/?q=seed.example"`,
		"https://ndxer.com/app/lookup/related/?q=seed.example",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("banner lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "test-key") {
		t.Error("banner leaks the key")
	}
	if strings.Contains(out.String(), "NOT added") {
		t.Error("banner reached the output writer")
	}
}

// rewriteTransport sends every request to the test server.
type rewriteTransport struct{ target string }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	target := strings.TrimPrefix(rt.target, "http://")
	u.Scheme, u.Host = "http", target
	clone := req.Clone(req.Context())
	clone.URL = &u
	return (&http.Transport{}).RoundTrip(clone)
}
