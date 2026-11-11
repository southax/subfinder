// Package ndxer logic
package ndxer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/southax/subfinder/v2/pkg/subscraping"
)

const (
	// hostnamesURL lists every distinct host ndxer holds under a domain, in
	// every position: names that own records, and hosts that other records
	// point at (CNAME, MX, NS and SPF targets, SOA primaries).
	hostnamesURL = "https://api.ndxer.com/v1/hostnames/"
	// pageLimit asks for the largest page any plan allows; the API clamps it
	// to the plan's page size, so fewer pages (and units) are spent per domain.
	pageLimit = 1000
)

// noWait is -ndxer-no-wait: take a partial list as it is, never wait.
var noWait atomic.Bool

// SetNoWait sets -ndxer-no-wait for every ndxer lookup in this process.
func SetNoWait(v bool) { noWait.Store(v) }

// NoWait reports whether -ndxer-no-wait is set.
func NoWait() bool { return noWait.Load() }

// Notices receives the lines that say ndxer is waiting or that a list is
// partial. It is os.Stderr and never gologger, whose only level that
// survives -silent writes to stdout and would pollute pipes.
var Notices io.Writer = os.Stderr

func noticef(format string, args ...any) {
	_, _ = fmt.Fprintf(Notices, format+"\n", args...)
}

// WaitNotice is the line printed once when a lookup starts to wait.
func WaitNotice(list, subject string, partial bool) string {
	minutes := int(PendingWait.Minutes())
	if partial {
		return fmt.Sprintf("ndxer is still adding %s for %s. Waiting up to %d minutes for the complete list; add -ndxer-no-wait to use what is there now instead.", list, subject, minutes)
	}
	return fmt.Sprintf("ndxer has not looked at %s before and is looking it up now. Waiting up to %d minutes for the answer; add -ndxer-no-wait to skip the wait.", subject, minutes)
}

// PartialNotice is the warning for a list used while ndxer was still adding to it.
// cut says the run's own time limit ended the wait.
func PartialNotice(list, subject string, capped, cut bool) string {
	if cut {
		return fmt.Sprintf("ndxer %s for %s were still partial when the run's time limit was reached; the run has what was there. Run subfinder again later to get the rest, or raise -max-time.", list, subject)
	}
	if capped {
		return fmt.Sprintf("ndxer %s for %s are still partial after waiting %d minutes; the run has what was there. Run subfinder again later to get the rest.", list, subject, int(PendingWait.Minutes()))
	}
	return fmt.Sprintf("ndxer %s for %s are partial: ndxer was still adding to them, and -ndxer-no-wait is set, so this run did not wait. Run subfinder again in a few minutes to get the rest, or drop -ndxer-no-wait to wait for them.", list, subject)
}

type pageResponse struct {
	Meta struct {
		// Status is "partial" on a first page that is valid but not complete yet.
		Status     string  `json:"status"`
		NextCursor *string `json:"next_cursor"`
		// UnitsToComplete is what the pages after this one cost;
		// UnitsRemaining is this month's allowance left after this page.
		UnitsToComplete *int `json:"units_to_complete"`
		UnitsRemaining  *int `json:"units_remaining"`
	} `json:"meta"`
	Matches []struct {
		Name string `json:"name"`
	} `json:"matches"`
}

type errorResponse struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// Source is the ndxer source: every hostname ndxer has observed under a domain.
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
	retry   *Backoff
}

// backoff returns the configured retry policy, or the default one.
func (s *Source) backoff() Backoff {
	b := DefaultBackoff()
	if s.retry != nil {
		b = *s.retry
	}
	b.NoWait = b.NoWait || NoWait()
	return b
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			stats.Skipped = true
			return
		}

		headers := map[string]string{
			"Authorization": "Bearer " + randomApiKey,
			"Accept":        "application/json",
			"User-Agent":    "subfinder",
		}

		suffix := "." + strings.ToLower(domain)
		seen := make(map[string]struct{})
		// emit sends a host under the domain once. It returns false when the
		// run must end: the context is done or -max-results is reached.
		emit := func(host string) bool {
			host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
			if !strings.HasSuffix(host, suffix) {
				return true
			}
			if _, ok := seen[host]; ok {
				return true
			}
			seen[host] = struct{}{}
			select {
			case <-ctx.Done():
				return false
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: host}:
				stats.Results++
			}
			// Every page costs a unit, so honor -max-results to bound quota use.
			return session.MaxResults == 0 || stats.Results < session.MaxResults
		}

		retry := s.backoff() // read once, before the first request; never held across sleeps
		retry.Note = func(partial bool) { noticef("%s", WaitNotice("hostnames", domain, partial)) }
		partial := &partialState{}
		err := s.run(ctx, session, domain, headers, &stats, emit, &retry, partial)
		if partial.seen && (partial.final || err != nil) {
			// Still partial when the run ended: what was there has been emitted.
			cut := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
			noticef("%s", PartialNotice("hostnames", domain, !retry.NoWait, cut))
		}
		if err == nil || errors.Is(err, errDone) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		stats.Errors++
	}()

	return results
}

// errDone ends a lookup early without reporting an error.
var errDone = errors.New("ndxer: done")

// partialState records whether a lookup saw a partial page (seen) and ended
// with one (final), so the run can say the list is partial.
type partialState struct{ seen, final bool }

// run follows the cursor to the end, passing every host to emit. A partial
// first page is emitted as soon as it arrives, so a wait cut short by the
// run's own time limit loses nothing; the complete page adds only new names.
func (s *Source) run(ctx context.Context, session *subscraping.Session, domain string, headers map[string]string, stats *subscraping.Statistics, emit func(string) bool, retry *Backoff, partial *partialState) error {
	var pendingWaited time.Duration
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		onPartial := func(page *pageResponse) {
			partial.seen = true
			for _, match := range page.Matches {
				if !emit(match.Name) {
					return
				}
			}
		}
		response, err := s.fetchPage(ctx, session, domain, cursor, headers, stats, retry, &pendingWaited, onPartial)
		var pe *PartialError
		if errors.As(err, &pe) {
			partial.final = true
			err = nil
		} else if err == nil && partial.seen {
			partial.seen = false // the complete page arrived
		}
		if err != nil {
			return err
		}
		if response == nil {
			// 404 not_found: ndxer has no data for this domain.
			return nil
		}

		for _, match := range response.Matches {
			if !emit(match.Name) {
				return errDone
			}
		}

		// Fail fast: a list the month's allowance cannot finish would spend
		// every unit left and still be partial. Keep the first page and stop,
		// unless -max-results already bounds the run.
		meta := response.Meta
		if cursor == "" && session.MaxResults == 0 && meta.UnitsToComplete != nil && meta.UnitsRemaining != nil && *meta.UnitsToComplete > *meta.UnitsRemaining {
			return fmt.Errorf("ndxer: listing every host under %s needs %d more units, %d left this month; kept the first page", domain, *meta.UnitsToComplete, *meta.UnitsRemaining)
		}

		next := meta.NextCursor
		if next == nil || *next == "" || *next == cursor {
			return nil
		}
		cursor = *next
	}
}

// fetchPage requests one page of hosts, retrying per the given policy.
// It returns a nil response and nil error when ndxer has no data (404).
// onPartial, when set, receives every partial page as it arrives.
func (s *Source) fetchPage(ctx context.Context, session *subscraping.Session, domain, cursor string, headers map[string]string, stats *subscraping.Statistics, retry *Backoff, pendingWaited *time.Duration, onPartial func(*pageResponse)) (*pageResponse, error) {
	var response *pageResponse
	err := retry.Await(ctx, domain, pendingWaited, func() error {
		page, err := s.fetchOnce(ctx, session, domain, cursor, headers, stats)
		response = page
		var pe *PendingError
		if page != nil && onPartial != nil && errors.As(err, &pe) && pe.Partial {
			onPartial(page)
		}
		return err
	})
	return response, err
}

// fetchOnce makes a single request for one page of hosts.
func (s *Source) fetchOnce(ctx context.Context, session *subscraping.Session, domain, cursor string, headers map[string]string, stats *subscraping.Statistics) (*pageResponse, error) {
	params := url.Values{"q": {domain}}
	params.Set("limit", strconv.Itoa(pageLimit))
	if cursor != "" {
		params.Set("cursor", cursor)
	}

	stats.Requests++
	resp, err := session.Get(ctx, hostnamesURL+"?"+params.Encode(), "", headers)
	defer session.DiscardHTTPResponse(resp)
	if err != nil {
		if resp == nil {
			return nil, Retryable(err, "")
		}
		if resp.StatusCode == http.StatusAccepted {
			// ndxer has not seen this domain yet and is still looking it up.
			return nil, &PendingError{RetryAfter: resp.Header.Get("Retry-After")}
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		// Surface ndxer's error code (e.g. quota_exceeded, rate_limited) and request id.
		var apiErr errorResponse
		if jsoniter.NewDecoder(resp.Body).Decode(&apiErr) == nil && apiErr.Error.Code != "" {
			reqErr := fmt.Errorf("%w: %s: %s (request_id=%s)", err, apiErr.Error.Code, apiErr.Error.Message, apiErr.Error.RequestID)
			if RetryableStatus(resp.StatusCode) {
				return nil, Retryable(reqErr, resp.Header.Get("Retry-After"))
			}
			return nil, reqErr
		}
		if RetryableStatus(resp.StatusCode) {
			return nil, Retryable(err, resp.Header.Get("Retry-After"))
		}
		return nil, err
	}

	var response pageResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, Retryable(fmt.Errorf("ndxer: decode response: %w", err), "")
	}
	if response.Meta.Status == StatusPartial {
		return &response, &PendingError{RetryAfter: resp.Header.Get("Retry-After"), Partial: true}
	}
	return &response, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "ndxer"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
