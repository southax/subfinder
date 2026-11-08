package ndxer

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestDelay_RetryAfterSeconds(t *testing.T) {
	b := Backoff{Base: time.Second, Jitter: func() float64 { return 0 }}
	if got := b.Delay(1, "7"); got != 7*time.Second {
		t.Errorf("Delay(1, \"7\") = %v, want 7s", got)
	}
}

func TestDelay_RetryAfterCapped(t *testing.T) {
	b := Backoff{Base: time.Second, MaxWait: 60 * time.Second, Jitter: func() float64 { return 0 }}
	if got := b.Delay(1, "600"); got != 60*time.Second {
		t.Errorf("Delay(1, \"600\") = %v, want 60s", got)
	}
}

func TestDelay_EqualJitterZero(t *testing.T) {
	b := Backoff{Base: time.Second, Jitter: func() float64 { return 0 }}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 500 * time.Millisecond},
		{2, 1 * time.Second},
		{3, 2 * time.Second},
	}
	for _, tc := range cases {
		if got := b.Delay(tc.attempt, ""); got != tc.want {
			t.Errorf("Delay(%d, \"\") = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestDelay_HugeAttempt(t *testing.T) {
	b := Backoff{Base: time.Second, MaxWait: 60 * time.Second, Jitter: func() float64 { return 1 }}
	got := b.Delay(100, "")
	if got > 60*time.Second {
		t.Errorf("Delay(100) = %v, want <= 60s", got)
	}
}

func TestDelay_HTTPDate(t *testing.T) {
	b := Backoff{Base: time.Second, MaxWait: 60 * time.Second, Jitter: func() float64 { return 0 }}
	future := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	got := b.Delay(1, future)
	if got < 1*time.Second || got > 10*time.Second {
		t.Errorf("Delay(1, HTTP-date ~10s) = %v, want between 1s and 10s", got)
	}
}

func TestRetry_CtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := Backoff{MaxAttempts: 3, Base: time.Millisecond, Sleep: func(context.Context, time.Duration) error { return nil }}
	err := b.Retry(ctx, func() error { return Retryable(context.Canceled, "") })
	if err != context.Canceled {
		t.Errorf("Retry returned %v, want context.Canceled", err)
	}
}

func TestSleepContext_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		done <- SleepContext(ctx, time.Hour)
	}()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("SleepContext = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SleepContext did not return promptly for cancelled ctx")
	}
}

func TestRetryable_Nil(t *testing.T) {
	if err := Retryable(nil, "x"); err != nil {
		t.Errorf("Retryable(nil) = %v, want nil", err)
	}
}

func TestPendingDelay(t *testing.T) {
	cases := []struct {
		retryAfter string
		want       time.Duration
	}{
		{"", 5 * time.Second},
		{"7", 7 * time.Second},
		{"600", 30 * time.Second},
		{"garbage", 5 * time.Second},
	}
	for _, tc := range cases {
		if got := PendingDelay(tc.retryAfter); got != tc.want {
			t.Errorf("PendingDelay(%q) = %v, want %v", tc.retryAfter, got, tc.want)
		}
	}
}

func TestAwait_PendingThenSuccess(t *testing.T) {
	var sleeps []time.Duration
	b := Backoff{
		MaxAttempts: 5,
		Base:        time.Second,
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	}
	var tried int
	waited := time.Duration(0)
	err := b.Await(context.Background(), "example.com", &waited, func() error {
		tried++
		if tried <= 2 {
			return &PendingError{RetryAfter: "2"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Await returned %v, want nil", err)
	}
	if len(sleeps) != 2 || sleeps[0] != 2*time.Second || sleeps[1] != 2*time.Second {
		t.Errorf("sleeps = %v, want [2s 2s]", sleeps)
	}
	if waited != 4*time.Second {
		t.Errorf("waited = %v, want 4s", waited)
	}
}

func TestAwait_BudgetExhausted(t *testing.T) {
	var sleeps []time.Duration
	b := Backoff{
		MaxAttempts: 5,
		Base:        time.Second,
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	}
	waited := time.Duration(0)
	err := b.Await(context.Background(), "example.com", &waited, func() error {
		return &PendingError{}
	})
	if err == nil || err.Error() != "ndxer is still looking up example.com; run again shortly" {
		t.Errorf("Await returned %v, want %q", err, "ndxer is still looking up example.com; run again shortly")
	}
	if waited != PendingWait {
		t.Errorf("waited = %v, want %v", waited, PendingWait)
	}
	var sum time.Duration
	for _, d := range sleeps {
		sum += d
	}
	if sum != PendingWait {
		t.Errorf("sum of sleeps = %v, want %v", sum, PendingWait)
	}
	if len(sleeps) != 24 {
		t.Errorf("len(sleeps) = %d, want 24", len(sleeps))
	}
}

func TestAwait_PendingDoesNotConsumeRetries(t *testing.T) {
	var sleeps []time.Duration
	b := Backoff{
		MaxAttempts: 2,
		Base:        time.Millisecond,
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
	}
	results := []error{
		Retryable(errors.New("503"), ""),
		&PendingError{RetryAfter: "1"},
		Retryable(errors.New("503"), ""),
		&PendingError{RetryAfter: "1"},
		nil,
	}
	i := 0
	err := b.Await(context.Background(), "example.com", nil, func() error {
		r := results[i]
		i++
		return r
	})
	if err != nil {
		t.Fatalf("Await returned %v, want nil", err)
	}
	if i != 5 {
		t.Errorf("try called %d times, want 5", i)
	}
}

func TestAwait_SleepCancelled(t *testing.T) {
	b := Backoff{
		MaxAttempts: 5,
		Base:        time.Second,
		Sleep: func(ctx context.Context, d time.Duration) error {
			return context.Canceled
		},
	}
	waited := time.Duration(0)
	err := b.Await(context.Background(), "example.com", &waited, func() error {
		return &PendingError{RetryAfter: "1"}
	})
	if err != context.Canceled {
		t.Errorf("Await returned %v, want context.Canceled", err)
	}
}
