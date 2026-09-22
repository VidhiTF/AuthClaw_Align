package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

func configureProviderTransport(transport *http.Transport) *http.Transport {
	transport.ResponseHeaderTimeout = 30 * time.Second
	return transport
}

// Renew deadlines per write so healthy streams can outlive a fixed request timeout.
type deadlineResponseWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
}

func (w *deadlineResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *deadlineResponseWriter) renew() error {
	return w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
}
func (w *deadlineResponseWriter) Write(body []byte) (int, error) {
	if err := w.renew(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(body)
}
func (w *deadlineResponseWriter) WriteHeader(status int) {
	if err := w.renew(); err != nil {
		panic(http.ErrAbortHandler)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *deadlineResponseWriter) FlushError() error {
	if err := w.renew(); err != nil {
		return err
	}
	return w.controller.Flush()
}
func (w *deadlineResponseWriter) Flush() { _ = w.FlushError() }

func responseWriteTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Time{}); err != nil {
			if errors.Is(err, http.ErrNotSupported) {
				next.ServeHTTP(w, r)
				return
			}
			panic(http.ErrAbortHandler)
		}
		// net/http flushes buffered headers/body after the handler returns.
		defer func() { _ = controller.SetWriteDeadline(time.Now().Add(timeout)) }()
		next.ServeHTTP(&deadlineResponseWriter{w, controller, timeout}, r)
	})
}

type readTimeoutTransport struct {
	next    http.RoundTripper
	timeout time.Duration
}

func providerReadTimeout(next http.RoundTripper, timeout time.Duration) http.RoundTripper {
	return readTimeoutTransport{next, timeout}
}

func (t readTimeoutTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t readTimeoutTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(r.Context())
	response, err := t.next.RoundTrip(r.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	body := &readTimeoutBody{ReadCloser: response.Body, cancel: cancel, timeout: t.timeout}
	body.timer = time.AfterFunc(t.timeout, cancel)
	body.timer.Stop()
	response.Body = body
	return response, nil
}

type readTimeoutBody struct {
	io.ReadCloser
	cancel  context.CancelFunc
	timeout time.Duration
	timer   *time.Timer
	mu      sync.Mutex
	closed  bool
}

func (b *readTimeoutBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, http.ErrBodyReadAfterClose
	}
	b.timer.Reset(b.timeout)
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	b.timer.Stop()
	b.mu.Unlock()
	return n, err
}

func (b *readTimeoutBody) Close() error {
	b.mu.Lock()
	b.closed = true
	b.timer.Stop()
	b.cancel()
	b.mu.Unlock()
	return b.ReadCloser.Close()
}
