package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/southax/subfinder/v2/pkg/subscraping/sources/ndxer"
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
"matches":[{"apex":"owned.example","class":"subject",
 "evidence":[{"kind":"name_label","key":"owned","n_apexes":9,"provider":null,"provider_name":null},{"kind":"mx_host","key":"mx.shared-owner.example","n_apexes":3,"provider":null,"provider_name":null}],
 "reasons":[{"code":"unique_value","text":"Shares the mail host mx.shared-owner.example."},{"code":"same_name","text":"Same first label."}]},
 {"apex":"maybe.example","class":"review","evidence":[{"kind":"name_label","key":"maybe","n_apexes":4,"provider":null,"provider_name":null}],"reasons":[{"code":"same_name_only","text":"Only the first label matches."}]}]}`)
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
		Host, Input, NdxerSeed, NdxerClass, NdxerWhy string
		NdxerEvidence                                any
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
		l.NdxerWhy, _ = m["ndxer_why"].(string)
		l.NdxerEvidence = m["ndxer_evidence"]
		got[l.Host] = l
	}
	if l := got["www.owned.example"]; l.NdxerSeed != "seed.example" || l.NdxerClass != "subject" {
		t.Errorf("added host not tagged: %+v (all: %v)", l, got)
	}
	if l := got["www.owned.example"]; l.NdxerWhy != "Shares the mail host mx.shared-owner.example." {
		t.Errorf("ndxer_why=%q", l.NdxerWhy)
	}
	raw, _ := jsoniter.Marshal(got["www.owned.example"].NdxerEvidence)
	var evidence []map[string]any
	_ = jsoniter.Unmarshal(raw, &evidence)
	if len(evidence) != 1 || len(evidence[0]) != 3 || evidence[0]["kind"] != "mx_host" || evidence[0]["key"] != "mx.shared-owner.example" || evidence[0]["n"] != float64(3) {
		t.Errorf("ndxer_evidence=%s (name_label must be dropped, no provider key)", raw)
	}
	for _, host := range []string{"www.seed.example", "www.second.example"} {
		if l := got[host]; l.NdxerWhy != "" || l.NdxerEvidence != nil {
			t.Errorf("%s must carry no ndxer_why/ndxer_evidence: %+v", host, l)
		}
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
		"https://ndxer.com/app/investigations/?q=seed.example",
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

// retryServer answers each hit with the next scripted response; the last one repeats.
type scripted struct {
	status     int
	retryAfter string
	body       string
}

func retryServer(t *testing.T, hits *atomic.Int64, script ...scripted) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(hits.Add(1))
		step := script[min(n, len(script))-1]
		if step.retryAfter != "" {
			w.Header().Set("Retry-After", step.retryAfter)
		}
		w.WriteHeader(step.status)
		_, _ = io.WriteString(w, step.body)
	}))
	t.Cleanup(server.Close)
	return server
}

func retryingClient(server *httptest.Server, sleeps *[]time.Duration) *relatedClient {
	return &relatedClient{baseURL: server.URL, key: "test-key", http: server.Client(), retry: ndxer.Backoff{
		MaxAttempts: 5,
		Base:        time.Second,
		Sleep: func(_ context.Context, d time.Duration) error {
			*sleeps = append(*sleeps, d)
			return nil
		},
		Jitter: func() float64 { return 0 },
	}}
}

const onePage = `{"meta":{"next_cursor":null,"units_charged":1},"matches":[{"apex":"owned.example","class":"subject"}]}`

func TestRelatedLookupRetries503(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusServiceUnavailable, body: `{"error":{"code":"unavailable","message":"busy","request_id":"r1"}}`},
		scripted{status: http.StatusOK, body: onePage})
	var sleeps []time.Duration
	result, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || len(result.ByClass[classSubject]) != 1 || len(sleeps) != 1 || sleeps[0] != 500*time.Millisecond {
		t.Errorf("hits=%d by=%v sleeps=%v", hits.Load(), result.ByClass, sleeps)
	}
}

func TestRelatedLookupWaitsRetryAfter(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusTooManyRequests, retryAfter: "2", body: `{"error":{"code":"rate_limited","message":"slow down","request_id":"r2"}}`},
		scripted{status: http.StatusOK, body: onePage})
	var sleeps []time.Duration
	if _, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Errorf("hits=%d sleeps=%v", hits.Load(), sleeps)
	}
}

func TestRelatedLookupRetriesTruncatedBody(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusOK, body: `{"meta":{"next_cursor":null},"matches":[{"apex":"owned.ex`},
		scripted{status: http.StatusOK, body: onePage})
	var sleeps []time.Duration
	result, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || len(result.ByClass[classSubject]) != 1 {
		t.Errorf("hits=%d by=%v", hits.Load(), result.ByClass)
	}
}

func TestRelatedLookupDoesNotRetry401(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusUnauthorized, body: `{"error":{"code":"unauthenticated","message":"bad key","request_id":"r3"}}`})
	var sleeps []time.Duration
	_, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example")
	var apiErr *relatedAPIError
	if !errors.As(err, &apiErr) || !apiErr.fatal() {
		t.Fatalf("err=%v", err)
	}
	if hits.Load() != 1 || len(sleeps) != 0 || !strings.Contains(err.Error(), "request_id=r3") {
		t.Errorf("hits=%d sleeps=%v err=%v", hits.Load(), sleeps, err)
	}
}

func TestRelatedLookupGivesUp(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusServiceUnavailable, body: `{"error":{"code":"unavailable","message":"busy","request_id":"r4"}}`})
	var sleeps []time.Duration
	_, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example")
	var apiErr *relatedAPIError
	if !errors.As(err, &apiErr) || apiErr.fatal() {
		t.Fatalf("err=%v", err)
	}
	if hits.Load() != 5 || len(sleeps) != 4 || !strings.Contains(err.Error(), "gave up after 5 attempts") || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("hits=%d sleeps=%v err=%v", hits.Load(), sleeps, err)
	}
}

func TestRelatedLookupPendingThenDone(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusAccepted, retryAfter: "4", body: `{"meta":{"status":"pending","next_cursor":null},"matches":[]}`},
		scripted{status: http.StatusOK, body: onePage})
	var sleeps []time.Duration
	result, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || len(result.ByClass[classSubject]) != 1 || len(sleeps) != 1 || sleeps[0] != 4*time.Second {
		t.Errorf("hits=%d by=%v sleeps=%v", hits.Load(), result.ByClass, sleeps)
	}
}

func TestRelatedLookupPendingGivesUp(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusAccepted, body: `{"meta":{"status":"pending","next_cursor":null},"matches":[]}`})
	var sleeps []time.Duration
	result, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example")
	if err == nil || !strings.Contains(err.Error(), "ndxer is still looking up seed.example; run again shortly") {
		t.Fatalf("err=%v", err)
	}
	if hits.Load() != 25 || len(result.ByClass) != 0 {
		t.Errorf("hits=%d by=%v", hits.Load(), result.ByClass)
	}
}

func TestRelatedLookupPendingRetryAfterCapped(t *testing.T) {
	var hits atomic.Int64
	server := retryServer(t, &hits,
		scripted{status: http.StatusAccepted, retryAfter: "600", body: `{"meta":{"status":"pending","next_cursor":null},"matches":[]}`},
		scripted{status: http.StatusOK, body: onePage})
	var sleeps []time.Duration
	if _, err := retryingClient(server, &sleeps).lookup(context.Background(), "seed.example"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || len(sleeps) != 1 || sleeps[0] != 30*time.Second {
		t.Errorf("hits=%d sleeps=%v", hits.Load(), sleeps)
	}
}

// A rate limit outlasting the retries must not switch related scope off for later seeds.
func TestRelatedRateLimitIsNotFatal(t *testing.T) {
	if (&relatedAPIError{Status: http.StatusTooManyRequests, Code: "rate_limited"}).fatal() {
		t.Error("429 must not be fatal")
	}
}

// TestRunnerRelatedFieldsWithCollectSources checks -oJ -cs: the sources array
// and the ndxer fields appear together on an added host.
func TestRunnerRelatedFieldsWithCollectSources(t *testing.T) {
	var hits atomic.Int64
	server := relatedServer(t, &hits, 0)

	previous := relatedBannerWriter
	relatedBannerWriter = io.Discard
	t.Cleanup(func() { relatedBannerWriter = previous })

	r := delayedRunner(t, 1, &delayedSource{delay: time.Millisecond})
	r.options.JSON = true
	r.options.CaptureSources = true
	r.related = &relatedSettings{key: "test-key", classes: []string{classSubject}}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = rewriteTransport{server.URL}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	var out bytes.Buffer
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("seed.example\n"), []io.Writer{&out}); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := jsoniter.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if m["host"] != "www.owned.example" {
			continue
		}
		found = true
		if sources, ok := m["sources"].([]any); !ok || len(sources) == 0 {
			t.Errorf("sources missing: %s", raw)
		}
		if m["ndxer_seed"] != "seed.example" || m["ndxer_class"] != "subject" || m["ndxer_why"] != "Shares the mail host mx.shared-owner.example." {
			t.Errorf("ndxer fields missing: %s", raw)
		}
		if ev, ok := m["ndxer_evidence"].([]any); !ok || len(ev) != 1 {
			t.Errorf("ndxer_evidence: %s", raw)
		}
	}
	if !found {
		t.Fatalf("added host missing from output:\n%s", out.String())
	}
}

func TestMatchEvidenceDropsNameLabel(t *testing.T) {
	cloud := "Example Cloud"
	got := matchEvidence([]apiEvidence{
		{Kind: "name_label", Key: "acme", NApexes: 9},
		{Kind: "ns_host", Key: "ns1.example-cloud.example", NApexes: 2, ProviderName: &cloud},
	})
	if len(got) != 1 || got[0] != (ndxerEvidence{Kind: "ns_host", Key: "ns1.example-cloud.example", N: 2, Provider: "Example Cloud"}) {
		t.Errorf("mixed: %+v", got)
	}
	got = matchEvidence([]apiEvidence{{Kind: "name_label", Key: "acme", NApexes: 9}})
	if len(got) != 1 || got[0].Kind != "name_label" {
		t.Errorf("name_label only must be kept: %+v", got)
	}
	if got := matchEvidence(nil); got != nil {
		t.Errorf("empty: %+v", got)
	}
}

func TestGroupByEvidence(t *testing.T) {
	mx := ndxerEvidence{Kind: "mx_host", Key: "mx.a.example", N: 3}
	token := ndxerEvidence{Kind: "verify_token", Key: "site-verification=T", N: 5}
	label := ndxerEvidence{Kind: "name_label", Key: "acme", N: 7}
	names := []string{"t1.example", "both1.example", "solo.example", "both2.example", "t2.example", "both3.example"}
	evidence := map[string][]ndxerEvidence{
		"both1.example": {mx, token},
		"both2.example": {token, mx}, // same set, other order
		"both3.example": {mx, token},
		"t1.example":    {token},
		"t2.example":    {token},
		"solo.example":  {label},
	}
	groups := groupByEvidence(names, evidence)
	if len(groups) != 3 {
		t.Fatalf("groups=%+v", groups)
	}
	want := [][]string{
		{"both1.example", "both2.example", "both3.example"},
		{"t1.example", "t2.example"},
		{"solo.example"},
	}
	for i, g := range groups {
		if strings.Join(g.Domains, " ") != strings.Join(want[i], " ") {
			t.Errorf("group %d = %v, want %v", i, g.Domains, want[i])
		}
	}
	if v := groups[0].Values; len(v) != 2 || v[0].Kind != "mx_host" || v[1].Kind != "verify_token" {
		t.Errorf("values not sorted by kind: %+v", v)
	}
}

func TestBannerGroupsAndTruncates(t *testing.T) {
	var banner bytes.Buffer
	previous := relatedBannerWriter
	relatedBannerWriter = &banner
	t.Cleanup(func() { relatedBannerWriter = previous })

	long := "google-site-verification=" + strings.Repeat("x", 75)
	result := &relatedResult{ByClass: map[string][]string{}, Evidence: map[string][]ndxerEvidence{}, Units: 3, Pages: 1}
	var names []string
	for i := range 8 {
		name := fmt.Sprintf("d%d.example", i)
		names = append(names, name)
		result.ByClass[classSubject] = append(result.ByClass[classSubject], name)
		result.Evidence[name] = []ndxerEvidence{{Kind: "verify_token", Key: long, N: 9}}
	}
	printRelatedBanner("seed.example", []string{classSubject}, result, map[string]int{classSubject: 8}, names)

	text := banner.String()
	for _, want := range []string{
		"Added 8 domains ndxer links to the same owner (8 subject)",
		"    8 share verify_token " + long[:60] + "…\n",
		"      d0.example d1.example d2.example d3.example d4.example d5.example … and 2 more\n",
		"Units charged by the related lookup: 3 (1 page)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("banner lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "d6.example") || strings.Contains(text, "\x1b[") {
		t.Errorf("banner shows a 7th domain or colour:\n%s", text)
	}
}
