package ndxer

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// partialServer answers a partial first page `partials` times, then the complete one.
func partialServer(t *testing.T, partials int32, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= partials {
			w.Header().Set("Retry-After", "4")
			_, _ = fmt.Fprint(w, `{"meta":{"status":"partial","next_cursor":null},"matches":[{"name":"a.hackerone.com"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"meta":{"status":null,"next_cursor":null},"matches":[{"name":"a.hackerone.com"},{"name":"b.hackerone.com"}]}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func captureNotices(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := Notices
	Notices = &buf
	t.Cleanup(func() { Notices = old })
	return &buf
}

func TestNdxerSource_PartialWaitsAndEmitsEarly(t *testing.T) {
	const domain = "hackerone.com"
	notices := captureNotices(t)
	var hits atomic.Int32
	server := partialServer(t, 2, &hits)

	var sleeps []time.Duration
	source := newRetryingSource(t, &sleeps)
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	// The partial page's name is emitted at once, the complete page adds only the new one.
	assert.Equal(t, []string{"a.hackerone.com", "b.hackerone.com"}, subs)
	assert.Equal(t, int32(3), hits.Load())
	assert.Equal(t, []time.Duration{4 * time.Second, 4 * time.Second}, sleeps)
	assert.Contains(t, notices.String(), "ndxer is still adding hostnames for hackerone.com")
	assert.NotContains(t, notices.String(), "partial")
}

func TestNdxerSource_PartialWithNoWait(t *testing.T) {
	const domain = "hackerone.com"
	notices := captureNotices(t)
	SetNoWait(true)
	t.Cleanup(func() { SetNoWait(false) })
	var hits atomic.Int32
	server := partialServer(t, 5, &hits)

	var sleeps []time.Duration
	source := newRetryingSource(t, &sleeps)
	subs, errs := runSource(t, source, newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, errs)
	assert.Equal(t, []string{"a.hackerone.com"}, subs)
	assert.Equal(t, int32(1), hits.Load())
	assert.Empty(t, sleeps)
	assert.Contains(t, notices.String(), "ndxer hostnames for hackerone.com are partial")
	assert.Contains(t, notices.String(), "-ndxer-no-wait")
}

func TestNdxerSource_PendingWithNoWaitDoesNotWait(t *testing.T) {
	const domain = "hackerone.com"
	captureNotices(t)
	SetNoWait(true)
	t.Cleanup(func() { SetNoWait(false) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, `{"meta":{"status":"pending","next_cursor":null},"matches":[]}`)
	}))
	t.Cleanup(server.Close)

	var sleeps []time.Duration
	subs, errs := runSource(t, newRetryingSource(t, &sleeps), newTestSession(t, server, domain, 0), domain)

	assert.Empty(t, subs)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "-ndxer-no-wait is set")
	assert.Empty(t, sleeps)
}

func TestPartialNoticeWording(t *testing.T) {
	assert.Contains(t, PartialNotice("hostnames", "example.com", true, false), "after waiting 15 minutes")
	assert.Contains(t, PartialNotice("hostnames", "example.com", false, true), "-max-time")
	assert.Contains(t, WaitNotice("related domains", "example.com", true), "-ndxer-no-wait")
}
