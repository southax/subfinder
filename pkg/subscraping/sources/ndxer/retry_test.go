package ndxer

import (
	"context"
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
