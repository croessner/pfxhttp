package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRequestLimiterDistinguishesQueueFullAndTimeout(t *testing.T) {
	limiter := NewRequestLimiter(t.Context(), 1, 1, 30*time.Millisecond)

	first, outcome := limiter.Acquire(t.Context())
	if first == nil || outcome != requestAdmitted {
		t.Fatalf("first acquire = (%v, %q), want admitted permit", first, outcome)
	}
	defer first.Release()

	timedOut := make(chan RequestAdmissionOutcome, 1)

	go func() {
		_, queuedOutcome := limiter.Acquire(t.Context())
		timedOut <- queuedOutcome
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)

	if permit, fullOutcome := limiter.Acquire(t.Context()); permit != nil || fullOutcome != requestQueueFull {
		t.Fatalf("full acquire = (%v, %q), want queue_full", permit, fullOutcome)
	}

	if got := <-timedOut; got != requestQueueTimeout {
		t.Fatalf("queued outcome = %q, want queue_timeout", got)
	}
}

func TestRequestLimiterServesQueuedRequestsFIFO(t *testing.T) {
	limiter := NewRequestLimiter(t.Context(), 1, 3, time.Second)
	first, _ := limiter.Acquire(t.Context())

	order := make(chan int, 3)
	permits := make(chan *RequestPermit, 3)

	for index := 1; index <= 3; index++ {
		index := index

		go func() {
			permit, outcome := limiter.Acquire(t.Context())
			if outcome != requestQueued {
				t.Errorf("waiter %d outcome = %q, want queued", index, outcome)
			}

			order <- index

			permits <- permit
		}()

		waitForLimiterSnapshot(t, limiter, 1, index)
	}

	first.Release()

	for want := 1; want <= 3; want++ {
		if got := <-order; got != want {
			t.Fatalf("grant order = %d, want %d", got, want)
		}

		(<-permits).Release()
	}
}

func TestRequestLimiterCancellationAndShutdownDoNotLeak(t *testing.T) {
	limiter := NewRequestLimiter(context.Background(), 1, 2, time.Second)
	first, _ := limiter.Acquire(context.Background())

	canceledCtx, cancel := context.WithCancel(context.Background())
	canceled := make(chan RequestAdmissionOutcome, 1)

	go func() {
		_, outcome := limiter.Acquire(canceledCtx)
		canceled <- outcome
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)
	cancel()

	if got := <-canceled; got != requestCallerCanceled {
		t.Fatalf("canceled outcome = %q", got)
	}

	shutdown := make(chan RequestAdmissionOutcome, 1)

	go func() {
		_, outcome := limiter.Acquire(context.Background())
		shutdown <- outcome
	}()

	waitForLimiterSnapshot(t, limiter, 1, 1)
	limiter.Stop()

	if got := <-shutdown; got != requestServerShutdown {
		t.Fatalf("shutdown outcome = %q", got)
	}

	first.Release()
	waitForLimiterSnapshot(t, limiter, 0, 0)
}

func TestRequestLimiterStopWinsQueuedGrantRace(t *testing.T) {
	for range 100 {
		limiter := NewRequestLimiter(context.Background(), 1, 1, time.Second)
		first, _ := limiter.Acquire(context.Background())
		shutdown := make(chan RequestAdmissionOutcome, 1)

		go func() {
			permit, outcome := limiter.Acquire(context.Background())
			if permit != nil {
				permit.Release()
			}

			shutdown <- outcome
		}()

		waitForLimiterSnapshot(t, limiter, 1, 1)
		limiter.Stop()
		first.Release()

		if got := <-shutdown; got != requestServerShutdown {
			t.Fatalf("queued outcome during stop/release = %q, want server_shutdown", got)
		}

		waitForLimiterSnapshot(t, limiter, 0, 0)
	}
}

func TestRequestLimiterReleasesCapacityAfterPanic(t *testing.T) {
	limiter := NewRequestLimiter(t.Context(), 1, 0, time.Second)

	outcome, err := limiter.Execute(t.Context(), func(context.Context) error { panic("synthetic") })
	if !errors.Is(err, errRequestExecutionPanic) || outcome != requestAdmitted {
		t.Fatalf("Execute() = (%v, %q), want contained panic", err, outcome)
	}

	permit, nextOutcome := limiter.Acquire(t.Context())
	if permit == nil || nextOutcome != requestAdmitted {
		t.Fatal("panic leaked request capacity")
	}

	permit.Release()
}

func TestRequestLimiterReleasesCapacityAfterSuccessAndBackendError(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "backend error", err: errors.New("synthetic backend failure")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			limiter := NewRequestLimiter(t.Context(), 1, 0, time.Second)

			outcome, err := limiter.Execute(t.Context(), func(context.Context) error { return testCase.err })
			if outcome != requestAdmitted || !errors.Is(err, testCase.err) {
				t.Fatalf("Execute() = (%q, %v), want admitted and %v", outcome, err, testCase.err)
			}

			permit, nextOutcome := limiter.Acquire(t.Context())
			if permit == nil || nextOutcome != requestAdmitted {
				t.Fatal("completed request leaked request capacity")
			}

			permit.Release()
		})
	}
}

func TestRequestLimitersOwnIndependentCapacity(t *testing.T) {
	first := NewRequestLimiter(t.Context(), 1, 0, time.Second)
	second := NewRequestLimiter(t.Context(), 1, 0, time.Second)

	firstPermit, _ := first.Acquire(t.Context())
	defer firstPermit.Release()

	secondPermit, outcome := second.Acquire(t.Context())
	if secondPermit == nil || outcome != requestAdmitted {
		t.Fatal("one listener consumed another listener's request capacity")
	}

	secondPermit.Release()
}

func waitForLimiterSnapshot(t *testing.T, limiter *RequestLimiter, wantInFlight, wantQueued int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		inFlight, queued := limiter.Snapshot()
		if inFlight == wantInFlight && queued == wantQueued {
			return
		}

		time.Sleep(time.Millisecond)
	}

	inFlight, queued := limiter.Snapshot()
	t.Fatalf("limiter snapshot = (%d, %d), want (%d, %d)", inFlight, queued, wantInFlight, wantQueued)
}
