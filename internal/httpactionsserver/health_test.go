package httpactionsserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthHandlerAnswersLivenessOnly(t *testing.T) {
	handler := HealthHandler()

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if resp.Code != http.StatusOK {
		t.Errorf("/healthz answered %d, want 200", resp.Code)
	}

	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/v1/actions/create-user-account", nil))
	if resp.Code != http.StatusNotFound {
		t.Errorf("the health listener serves the actions API: answered %d, want 404", resp.Code)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestStartServesLivenessApartFromTheActionsAPI(t *testing.T) {
	cfg := NewServerConfig()
	cfg.Addr = freeAddr(t)
	cfg.HealthProbeAddr = freeAddr(t)
	svr := NewServer(cfg, nil, nil, nil)

	errs := make(chan error, 1)
	go func() { errs <- svr.Start() }()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-errs:
			t.Fatalf("Start returned: %v", err)
		default:
		}
		resp, err := client.Get("http://" + cfg.HealthProbeAddr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("/healthz answered %d, want 200", resp.StatusCode)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no liveness endpoint on %s: %v", cfg.HealthProbeAddr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestStartFailsWhenTheHealthAddressIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = taken.Close() }()

	cfg := NewServerConfig()
	cfg.Addr = freeAddr(t)
	cfg.HealthProbeAddr = taken.Addr().String()

	if err := NewServer(cfg, nil, nil, nil).Start(); err == nil {
		t.Error("Start succeeded with the health address already in use")
	}
}
