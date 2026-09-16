package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviderReadTimeoutCancelsStalledBody(t *testing.T) {
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	client := &http.Client{Transport: providerReadTimeout(http.DefaultTransport, 100*time.Millisecond), Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	started := time.Now()
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("stalled response completed without error")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("body was stopped by the client total timeout instead of idle timeout")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream request was not canceled")
	}
}

func TestProviderReadTimeoutAllowsLongActiveStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 8; i++ {
			_, _ = io.WriteString(w, "data: chunk\n")
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer server.Close()
	client := &http.Client{Transport: providerReadTimeout(http.DefaultTransport, 300*time.Millisecond), Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != strings.Repeat("data: chunk\n", 8) {
		t.Fatalf("active stream interrupted: %q %v", body, err)
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestResponseWriteTimeoutBoundsFinalServerFlush(t *testing.T) {
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	responseWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "buffered")
	}), time.Second).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if remaining := time.Until(w.deadline); remaining <= 0 || remaining > time.Second {
		t.Fatalf("final flush has no valid bounded deadline: %v", w.deadline)
	}
}

func TestResponseWriteTimeoutStopsBlockedClient(t *testing.T) {
	done := make(chan error, 1)
	server := httptest.NewServer(responseWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 64*1024)
		for {
			if _, err := w.Write(chunk); err != nil {
				done <- err
				return
			}
		}
	}), 100*time.Millisecond))
	defer server.Close()
	connection, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if network, ok := err.(net.Error); !ok || !network.Timeout() {
			t.Fatalf("want write timeout, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked client retained the handler")
	}
}

func TestResponseWriteTimeoutRenewsForLongStream(t *testing.T) {
	server := httptest.NewServer(responseWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 3; i++ {
			if _, err := fmt.Fprintln(w, "data: chunk"); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
	}), 50*time.Millisecond))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner, count := bufio.NewScanner(response.Body), 0
	for scanner.Scan() {
		if scanner.Text() != "data: chunk" {
			t.Fatal(scanner.Text())
		}
		count++
	}
	if scanner.Err() != nil || count != 3 {
		t.Fatalf("stream interrupted: count=%d error=%v", count, scanner.Err())
	}
}

func TestResponseWriteTimeoutPreservesRecorder(t *testing.T) {
	writer := httptest.NewRecorder()
	responseWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }), time.Second).ServeHTTP(writer, httptest.NewRequest("GET", "/", nil))
	if writer.Body.String() != "ok" {
		t.Fatal(writer.Body.String())
	}
}
