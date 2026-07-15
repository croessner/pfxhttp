package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RequestAdmissionOutcome is a bounded result of request permit acquisition.
type RequestAdmissionOutcome string

const (
	requestAdmitted       RequestAdmissionOutcome = "admitted"
	requestQueued         RequestAdmissionOutcome = "queued"
	requestQueueFull      RequestAdmissionOutcome = "queue_full"
	requestQueueTimeout   RequestAdmissionOutcome = "queue_timeout"
	requestCallerCanceled RequestAdmissionOutcome = "caller_canceled"
	requestServerShutdown RequestAdmissionOutcome = "server_shutdown"
)

var errRequestExecutionPanic = errors.New("request execution panic")

type requestWaiter struct {
	ready    chan struct{}
	granted  bool
	queuedAt time.Time
}

type requestLimiterEvent struct {
	outcome       RequestAdmissionOutcome
	inFlightDelta int
	queuedDelta   int
	queueWait     time.Duration
}

// RequestPermit releases one in-flight execution slot exactly once.
type RequestPermit struct {
	limiter *RequestLimiter
	once    sync.Once
}

// Release returns the execution slot to the listener limiter.
func (p *RequestPermit) Release() {
	if p == nil || p.limiter == nil {
		return
	}

	p.once.Do(p.limiter.release)
}

// RequestLimiter bounds in-flight and queued application work for one listener.
type RequestLimiter struct {
	ctx          context.Context
	cancel       context.CancelFunc
	maxInFlight  int
	maxQueued    int
	queueTimeout time.Duration

	mu       sync.Mutex
	inFlight int
	waiters  []*requestWaiter
	stopped  bool
	stopOnce sync.Once
	observer func(requestLimiterEvent)
}

func (l *RequestLimiter) SetObserver(observer func(requestLimiterEvent)) {
	l.mu.Lock()
	l.observer = observer
	l.mu.Unlock()
}

// NewRequestLimiter creates independent request scheduling for one listener.
func NewRequestLimiter(parent context.Context, maxInFlight, maxQueued int, queueTimeout time.Duration) *RequestLimiter {
	ctx, cancel := context.WithCancel(parent)

	return &RequestLimiter{
		ctx:          ctx,
		cancel:       cancel,
		maxInFlight:  max(1, maxInFlight),
		maxQueued:    max(0, maxQueued),
		queueTimeout: queueTimeout,
	}
}

// Acquire obtains an execution permit or a stable rejection outcome.
func (l *RequestLimiter) Acquire(ctx context.Context) (*RequestPermit, RequestAdmissionOutcome) {
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		l.notify(requestLimiterEvent{outcome: requestServerShutdown})

		return nil, requestServerShutdown
	}

	if l.inFlight < l.maxInFlight {
		l.inFlight++
		l.mu.Unlock()
		l.notify(requestLimiterEvent{outcome: requestAdmitted, inFlightDelta: 1})

		return &RequestPermit{limiter: l}, requestAdmitted
	}

	if len(l.waiters) >= l.maxQueued {
		l.mu.Unlock()
		l.notify(requestLimiterEvent{outcome: requestQueueFull})

		return nil, requestQueueFull
	}

	waiter := &requestWaiter{ready: make(chan struct{}), queuedAt: time.Now()}
	l.waiters = append(l.waiters, waiter)
	l.mu.Unlock()
	l.notify(requestLimiterEvent{queuedDelta: 1})

	timer := time.NewTimer(l.queueTimeout)
	defer timer.Stop()

	select {
	case <-waiter.ready:
		l.mu.Lock()
		if l.stopped {
			l.inFlight--
			l.mu.Unlock()
			l.notify(requestLimiterEvent{outcome: requestServerShutdown, inFlightDelta: -1, queueWait: time.Since(waiter.queuedAt)})

			return nil, requestServerShutdown
		}
		l.mu.Unlock()
		l.notify(requestLimiterEvent{outcome: requestQueued, queueWait: time.Since(waiter.queuedAt)})

		return &RequestPermit{limiter: l}, requestQueued
	case <-ctx.Done():
		return l.cancelWaiter(waiter, requestCallerCanceled)
	case <-l.ctx.Done():
		return l.cancelWaiter(waiter, requestServerShutdown)
	case <-timer.C:
		return l.cancelWaiter(waiter, requestQueueTimeout)
	}
}

func (l *RequestLimiter) cancelWaiter(waiter *requestWaiter, outcome RequestAdmissionOutcome) (*RequestPermit, RequestAdmissionOutcome) {
	l.mu.Lock()
	if waiter.granted {
		l.mu.Unlock()
		l.release()
		l.notify(requestLimiterEvent{outcome: outcome, queueWait: time.Since(waiter.queuedAt)})

		return nil, outcome
	}

	for index, queued := range l.waiters {
		if queued == waiter {
			l.waiters = append(l.waiters[:index], l.waiters[index+1:]...)

			break
		}
	}
	l.mu.Unlock()
	l.notify(requestLimiterEvent{outcome: outcome, queuedDelta: -1, queueWait: time.Since(waiter.queuedAt)})

	return nil, outcome
}

func (l *RequestLimiter) release() {
	l.mu.Lock()

	if l.stopped || len(l.waiters) == 0 {
		l.inFlight--
		l.mu.Unlock()
		l.notify(requestLimiterEvent{inFlightDelta: -1})

		return
	}

	waiter := l.waiters[0]
	l.waiters = l.waiters[1:]
	waiter.granted = true
	close(waiter.ready)
	l.mu.Unlock()
	l.notify(requestLimiterEvent{queuedDelta: -1})
}

func (l *RequestLimiter) notify(event requestLimiterEvent) {
	l.mu.Lock()
	observer := l.observer
	l.mu.Unlock()

	if observer != nil {
		observer(event)
	}
}

// Execute runs application work under a permit and contains panics without leaking capacity.
func (l *RequestLimiter) Execute(ctx context.Context, work func(context.Context) error) (outcome RequestAdmissionOutcome, err error) {
	permit, outcome := l.Acquire(ctx)
	if permit == nil {
		return outcome, nil
	}
	defer permit.Release()
	defer func() {
		if recover() != nil {
			err = errRequestExecutionPanic
		}
	}()

	return outcome, work(ctx)
}

// Stop cancels queued acquisition and rejects future requests.
func (l *RequestLimiter) Stop() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.stopped = true
		l.mu.Unlock()
		l.cancel()
	})
}

// Snapshot returns current in-flight and queued counts for tests and observability.
func (l *RequestLimiter) Snapshot() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.inFlight, len(l.waiters)
}
