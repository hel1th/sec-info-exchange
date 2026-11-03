// Command demo checks a running service using API keys from the environment.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const infoPath = "/info/"

func run() error {
	base := os.Getenv("BASE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	reader, writer := os.Getenv("API_READER_KEY"), os.Getenv("API_WRITER_KEY")
	if reader == "" || writer == "" {
		return fmt.Errorf("set API_READER_KEY and API_WRITER_KEY")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(random[:])
	body := `{"md5":"` + id + `","name":"Demo","severity":"high"}`
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		method, path, key, body string
		status                  int
	}{
		{http.MethodGet, "/healthz", "", "", http.StatusOK},
		{http.MethodGet, "/readyz", "", "", http.StatusOK},
		{http.MethodGet, "/info/" + id, "", "", http.StatusUnauthorized},
		{http.MethodPost, infoPath, reader, body, http.StatusForbidden},
		{http.MethodPost, infoPath, writer, body, http.StatusCreated},
		{http.MethodPost, infoPath, writer, body, http.StatusConflict},
		{http.MethodGet, infoPath + id, reader, "", http.StatusOK},
		{http.MethodPut, infoPath + id, writer, `{"name":"Updated","severity":"low"}`, http.StatusOK},
	} {
		status, err := request(ctx, client, base+tc.path, tc.method, tc.key, tc.body)
		if err != nil {
			return err
		}
		if status != tc.status {
			return fmt.Errorf("%s %s: got %d, want %d", tc.method, tc.path, status, tc.status)
		}
		fmt.Printf("%s %s -> %d\n", tc.method, tc.path, status)
	}
	for range 1000 {
		status, err := request(ctx, client, base+infoPath+id, http.MethodGet, reader, "")
		if err != nil {
			return err
		}
		if status == http.StatusTooManyRequests {
			fmt.Println("Rate limit -> 429")
			return nil
		}
		if status != http.StatusOK {
			return fmt.Errorf("rate-limit probe returned %d", status)
		}
	}
	return fmt.Errorf("no 429 within 1000 requests; use default rate limits for demo")
}

func request(ctx context.Context, client *http.Client, url, method, key, body string) (int, error) {
	// #nosec G704 -- CLI target is explicitly supplied by the local operator.
	r, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	r.Header.Set("X-API-Key", key)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r) // #nosec G704 -- This CLI intentionally sends requests to its configured target.
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return 0, err
	}
	return response.StatusCode, nil
}
