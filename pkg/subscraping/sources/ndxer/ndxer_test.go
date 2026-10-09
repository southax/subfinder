package ndxer

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rewriteTransport struct {
	target *url.URL
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = r.target.Scheme
	req.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestSession(t *testing.T, server *httptest.Server, domain string, maxResults int) *subscraping.Session {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	extractor, err := subscraping.NewSubdomainExtractor(domain)
	require.NoError(t, err)

	mrl, err := ratelimit.NewMultiLimiter(context.Background(), &ratelimit.Options{
		Key:         "ndxer",
		IsUnlimited: false,
		MaxCount:    math.MaxInt32,
		Duration:    time.Millisecond,
	})
	require.NoError(t, err)

	return &subscraping.Session{
		Client:           &http.Client{Transport: &rewriteTransport{target: target}, Timeout: 5 * time.Second},
		MultiRateLimiter: mrl,
		Extractor:        extractor,
		MaxResults:       maxResults,
	}
}

func runSource(t *testing.T, source *Source, session *subscraping.Session, domain string) (subs []string, errs []error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "ndxer")

	for r := range source.Run(ctx, domain, session) {
		switch r.Type {
		case subscraping.Subdomain:
			subs = append(subs, r.Value)
		case subscraping.Error:
			errs = append(errs, r.Error)
		}
	}
	return
}

func page(cursor string, hosts ...string) string {
	next := "null"
	if cursor != "" {
		next = fmt.Sprintf("%q", cursor)
	}
	rows := make([]string, 0, len(hosts))
	for _, host := range hosts {
		rows = append(rows, fmt.Sprintf(`{"name":%q,"value":"","type":"","apex":null,"first_observed":null,"last_observed":null,"seen_as":["owner"]}`, host))
	}
	return fmt.Sprintf(`{"meta":{"next_cursor":%s,"units_charged":1},"matches":[%s]}`, next, strings.Join(rows, ","))
}

func TestNdxerSource_Metadata(t *testing.T) {
	source := &Source{}
	assert.Equal(t, "ndxer", source.Name())
	assert.True(t, source.IsDefault())
	assert.True(t, source.HasRecursiveSupport())
	assert.True(t, source.NeedsKey())
	assert.Equal(t, subscraping.RequiredKey, source.KeyRequirement())
}

func TestNdxerSource_SkipsWithoutKey(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	subs, errs := runSource(t, source, newTestSession(t, server, "hackerone.com", 0), "hackerone.com")

	assert.Empty(t, subs)
	assert.Empty(t, errs)
	assert.True(t, source.Statistics().Skipped)
	assert.Zero(t, hits.Load())
}

func TestNdxerSource_QueriesHostnames(t *testing.T) {
	const domain = "hackerone.com"
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		assert.Equal(t, "/v1/hostnames/", r.URL.Path)
		assert.Equal(t, domain, r.URL.Query().Get("q"))
		assert.Equal(t, "1000", r.URL.Query().Get("limit"))
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, page(""))
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	_, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Equal(t, int32(1), hits.Load())
	assert.Equal(t, 1, source.Statistics().Requests)
}

func TestNdxerSource_Paginates(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = fmt.Fprint(w, page("c2", "hackerone.com", "www.hackerone.com"))
		case "c2":
			_, _ = fmt.Fprint(w, page("", "api.hackerone.com"))
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.hackerone.com", "api.hackerone.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Requests)
}

func TestNdxerSource_KeepsOnlyHostsUnderDomain(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, page("", "hackerone.com", "MX1.hackerone.com.", "mx1.hackerone.com", "hackerone.com.evil.net", "nothackerone.com", ""))
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"mx1.hackerone.com"}, subs)
	assert.Equal(t, 1, source.Statistics().Results)
}

func TestNdxerSource_MaxResultsStopsPaging(t *testing.T) {
	const domain = "hackerone.com"
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, page("more", "a.hackerone.com", "b.hackerone.com", "c.hackerone.com"))
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 2), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"a.hackerone.com", "b.hackerone.com"}, subs)
	assert.Equal(t, int32(1), hits.Load())
}

func TestNdxerSource_NotFoundIsNoData(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"error":{"code":"not_found","message":"nothing","request_id":"r1"}}`)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, subs)
	assert.Empty(t, errs)
	assert.Zero(t, source.Statistics().Errors)
}

func TestNdxerSource_AccountErrorIsReported(t *testing.T) {
	const domain = "hackerone.com"
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":"quota_exceeded","message":"Allowance used up.","request_id":"r2"}}`)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "403")
	assert.Contains(t, errs[0].Error(), "quota_exceeded")
	assert.Contains(t, errs[0].Error(), "request_id=r2")
	assert.Equal(t, int32(1), hits.Load())
}

func TestNdxerSource_StopsWhenAllowanceCannotFinish(t *testing.T) {
	const domain = "hackerone.com"
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, `{"meta":{"next_cursor":"c2","units_charged":1,"units_to_complete":40,"units_remaining":12},"matches":[{"name":"www.hackerone.com","value":"","type":""}]}`)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Equal(t, []string{"www.hackerone.com"}, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "needs 40 more units, 12 left this month")
	assert.Equal(t, int32(1), hits.Load())
}

func TestNdxerSource_PagesOnWhenAllowanceSuffices(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = fmt.Fprint(w, `{"meta":{"next_cursor":"c2","units_to_complete":1,"units_remaining":1},"matches":[{"name":"www.hackerone.com"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"meta":{"next_cursor":null,"units_to_complete":0,"units_remaining":0},"matches":[{"name":"api.hackerone.com"}]}`)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"www.hackerone.com", "api.hackerone.com"}, subs)
}

func TestNdxerSource_PageErrorKeepsEarlierHosts(t *testing.T) {
	const domain = "hackerone.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = fmt.Fprint(w, page("c2", "www.hackerone.com"))
			return
		}
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = fmt.Fprint(w, `{"error":{"code":"timeout","message":"Lookup took too long.","request_id":"r3"}}`)
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "timeout")
	assert.Equal(t, []string{"www.hackerone.com"}, subs)
	assert.Equal(t, 2, source.Statistics().Requests)
	assert.Equal(t, 1, source.Statistics().Errors)
}

func TestNdxerSource_ContextCancel(t *testing.T) {
	const domain = "hackerone.com"
	started := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		time.Sleep(2 * time.Second)
		_, _ = fmt.Fprint(w, page("", "www.hackerone.com"))
	}))
	t.Cleanup(server.Close)

	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	session := newTestSession(t, server, domain, 0)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, "ndxer")

	results := source.Run(ctx, domain, session)
	<-started
	cancel()

	for r := range results {
		if r.Type == subscraping.Subdomain {
			t.Fatalf("got subdomain after cancel: %s", r.Value)
		}
	}
}
