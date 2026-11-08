package ndxer

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Backoff is the retry policy ndxer's API docs ask clients to follow: on 429
// wait Retry-After, on 502/503/504 back off exponentially with jitter, and
// never retry another 4xx. Transport errors and a truncated or undecodable
// 200 body are retried too. The zero value is usable: one attempt, real sleep.
type Backoff struct {
	MaxAttempts int                                              // total attempts including the first; <1 means 1
	Base        time.Duration                                    // first backoff step; 0 means 1s
	MaxWait     time.Duration                                    // cap on any single wait; 0 means 60s
	Sleep       func(ctx context.Context, d time.Duration) error // nil means SleepContext; tests replace it
	Jitter      func() float64                                   // returns [0,1); nil means math/rand/v2 Float64
}

// DefaultBackoff is the policy ndxer's API docs ask clients to follow:
// up to five attempts, doubling from one second, capped at a sixty-second wait.
func DefaultBackoff() Backoff {
	return Backoff{
		MaxAttempts: 5,
		Base:        time.Second,
		MaxWait:     60 * time.Second,
		Sleep:       SleepContext,
		Jitter:      rand.Float64,
	}
}

// SleepContext waits d, or returns ctx.Err() as soon as ctx is done.
func SleepContext(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		time.Sleep(d)
		return nil
	}
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RetryableStatus reports whether ndxer's docs say the given status is
// transient: 429, 502, 503 and 504 only.
func RetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableError marks an error as worth another attempt.
type retryableError struct {
	err        error
	retryAfter string
}

func (r *retryableError) Error() string { return r.err.Error() }
func (r *retryableError) Unwrap() error { return r.err }

// Retryable marks err as worth another attempt. retryAfter is the response's
// Retry-After header value, "" when there is none. Retryable(nil, x) returns nil.
func Retryable(err error, retryAfter string) error {
	if err == nil {
		return nil
	}
	return &retryableError{err: err, retryAfter: retryAfter}
}

// Delay is the wait to perform after the attempt numbered attempt (1-based)
// failed. A Retry-After header naming a positive number of seconds, or an
// HTTP date in the future, wins; otherwise the step is Base doubled
// (attempt-1) times, halved, plus a jittered half-step; the result is
// capped at MaxWait.
func (b Backoff) Delay(attempt int, retryAfter string) time.Duration {
	base := b.Base
	if base <= 0 {
		base = time.Second
	}
	maxWait := b.MaxWait
	if maxWait <= 0 {
		maxWait = 60 * time.Second
	}
	jitter := b.Jitter
	if jitter == nil {
		jitter = rand.Float64
	}

	if retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
			return min(time.Duration(secs)*time.Second, maxWait)
		}
		if ts, err := http.ParseTime(retryAfter); err == nil {
			if wait := time.Until(ts); wait > 0 {
				return min(wait, maxWait)
			}
		}
	}

	// Double Base per failed attempt; past about 30 doublings, or once the
	// step reaches MaxWait, the step is MaxWait.
	step := maxWait
	if n := max(attempt-1, 0); n < 30 {
		if shifted := base << n; shifted > 0 && shifted < maxWait {
			step = shifted
		}
	}
	d := step/2 + time.Duration(jitter()*float64(step/2))
	return min(d, maxWait)
}

// Retry calls try until it returns nil, returns an error that is not marked
// retryable, or MaxAttempts attempts have been used. A nil result or a
// non-retryable error is returned unchanged; a retryable error with a done
// context returns the context error; the final retryable error is wrapped
// with the number of attempts made.
func (b Backoff) Retry(ctx context.Context, try func() error) error {
	attempts := b.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	sleep := b.Sleep
	if sleep == nil {
		sleep = SleepContext
	}

	for attempt := 1; ; attempt++ {
		err := try()
		var retryable *retryableError
		if err == nil || !errors.As(err, &retryable) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= attempts {
			return fmt.Errorf("%w (gave up after %d attempts)", retryable.err, attempts)
		}
		if err := sleep(ctx, b.Delay(attempt, retryable.retryAfter)); err != nil {
			return err
		}
	}
}
