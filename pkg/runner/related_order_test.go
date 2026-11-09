package runner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/southax/subfinder/v2/pkg/passive"
	"github.com/southax/subfinder/v2/pkg/subscraping"
)

// orderSource records when each domain's enumeration starts and ends.
type orderSource struct {
	delay  time.Duration
	mu     sync.Mutex
	events []string
}

func (s *orderSource) record(event string) {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
}

func (s *orderSource) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		s.record("start:" + domain)
		defer s.record("end:" + domain)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.delay):
		}
		select {
		case <-ctx.Done():
		case results <- subscraping.Result{Type: subscraping.Subdomain, Source: s.Name(), Value: "www." + domain}:
		}
	}()
	return results
}
func (*orderSource) Name() string                               { return "order-recorder" }
func (*orderSource) IsDefault() bool                            { return false }
func (*orderSource) HasRecursiveSupport() bool                  { return true }
func (*orderSource) NeedsKey() bool                             { return false }
func (*orderSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (*orderSource) AddApiKeys([]string)                        {}
func (*orderSource) Statistics() subscraping.Statistics         { return subscraping.Statistics{} }

// TestRelatedDomainsStartAfterEverySeed: with several workers free, a related
// domain must not start until every domain the user passed has finished, so
// related domains never compete with the seeds for the sources' rate limits.
func TestRelatedDomainsStartAfterEverySeed(t *testing.T) {
	var hits atomic.Int64
	server := relatedServer(t, &hits, 0)

	var banner bytes.Buffer
	previous := relatedBannerWriter
	relatedBannerWriter = &banner
	t.Cleanup(func() { relatedBannerWriter = previous })

	oldTransport := http.DefaultTransport
	http.DefaultTransport = rewriteTransport{server.URL}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	source := &orderSource{delay: 150 * time.Millisecond}
	name := source.Name()
	saved, existed := passive.NameSourceMap[name]
	passive.NameSourceMap[name] = source
	t.Cleanup(func() {
		if existed {
			passive.NameSourceMap[name] = saved
		} else {
			delete(passive.NameSourceMap, name)
		}
	})
	r := &Runner{
		options:         &Options{Threads: 4, Timeout: 1, MaxEnumerationTime: 1},
		passiveAgent:    passive.New([]string{name}, nil, false, false),
		newPassiveAgent: func() *passive.Agent { return passive.New([]string{name}, nil, false, false) },
		related:         &relatedSettings{key: "test-key", classes: []string{classSubject}},
	}

	var out bytes.Buffer
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("seed.example\nsecond.example\n"), []io.Writer{&out}); err != nil {
		t.Fatal(err)
	}

	source.mu.Lock()
	events := append([]string(nil), source.events...)
	source.mu.Unlock()

	index := func(event string) int {
		for i, e := range events {
			if e == event {
				return i
			}
		}
		return -1
	}
	related := index("start:owned.example")
	if related < 0 {
		t.Fatalf("related domain never enumerated; events=%v", events)
	}
	for _, seed := range []string{"seed.example", "second.example"} {
		if end := index("end:" + seed); end < 0 || end > related {
			t.Errorf("%s ended at %d, related domain started at %d; events=%v", seed, end, related, events)
		}
	}
	if !strings.Contains(out.String(), "www.owned.example") {
		t.Errorf("related host missing from output: %q", out.String())
	}
}
