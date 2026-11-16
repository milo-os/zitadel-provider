package webhookserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
	token "go.miloapis.com/auth-provider-zitadel/pkg/token"
)

// On SIGTERM the manager cancels the webhook server's start context, and
// controller-runtime uses that context as the base of every request. A token
// check in flight at that moment must still get Zitadel's answer, not
// "context canceled": Milo's API server never retries a denied TokenReview.
func TestTokenCheckInFlightGetsZitadelsAnswerWhenTheServerShutsDown(t *testing.T) {
	zitadel := newBlockingZitadel(t)
	server := startWebhookServer(t, zitadel.URL)
	answered := postTokenReview(server)
	receive(t, zitadel.arrived, 10*time.Second, "the token check never reached the Zitadel stand-in")

	// SIGTERM: the manager cancels the server's context. Wait until the server
	// has closed its listener, so the check is in flight during the shutdown.
	server.cancel()
	waitUntilListenerClosed(t, server.addr)
	close(zitadel.release)

	got := receive(t, answered, 15*time.Second, "the token check got no answer")
	assertZitadelsAnswer(t, got)
	if err := receive(t, server.stopped, 10*time.Second, "the webhook server did not finish its shutdown"); err != nil {
		t.Fatalf("the webhook server stopped with an error: %v", err)
	}
}

// Every endpoint registers through shutdownSafeRegistrar, so a request whose
// base context the shutdown has cancelled still runs, but never past
// requestTimeout.
func TestEveryEndpointRunsOnAContextTheShutdownDoesNotCancelButThatIsBounded(t *testing.T) {
	reg := handlerRegistrar{}
	var seenErr error
	var deadline time.Time
	var hasDeadline bool
	shutdownSafeRegistrar{reg}.Register("/endpoint", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenErr = r.Context().Err()
		deadline, hasDeadline = r.Context().Deadline()
	}))

	shutDown, cancel := context.WithCancel(context.Background())
	cancel()
	reg["/endpoint"].ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/endpoint", nil).WithContext(shutDown))
	served := time.Now()

	if seenErr != nil {
		t.Fatalf("the shutdown's cancel reached the handler: %v", seenErr)
	}
	if !hasDeadline || deadline.After(served.Add(requestTimeout)) {
		t.Fatalf("want a deadline at most %s after the request, got %v after it (set: %v)",
			requestTimeout, deadline.Sub(served), hasDeadline)
	}
}

// handlerRegistrar keeps each handler registered on it, by path.
type handlerRegistrar map[string]http.Handler

func (r handlerRegistrar) Register(path string, hook http.Handler) { r[path] = hook }

// blockingZitadel stands in for Zitadel's introspection endpoint. It signals
// arrived when a check reaches it, and answers "active" once release closes.
type blockingZitadel struct {
	*httptest.Server
	arrived chan struct{}
	release chan struct{}
}

func newBlockingZitadel(t *testing.T) *blockingZitadel {
	t.Helper()
	z := &blockingZitadel{arrived: make(chan struct{}), release: make(chan struct{})}
	z.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(z.arrived)
		select {
		case <-z.release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "sub": "user-1", "email": "user@example.com", "email_verified": true,
		})
	}))
	t.Cleanup(z.Close)
	return z
}

// webhookServer is controller-runtime's webhook server with the command's
// endpoints, running on a context the test cancels as SIGTERM would.
type webhookServer struct {
	addr    string
	client  *http.Client
	cancel  context.CancelFunc
	stopped chan error
}

func startWebhookServer(t *testing.T, zitadelURL string) *webhookServer {
	t.Helper()
	introspector, err := token.NewIntrospector(writeApplicationKey(t), zitadelURL, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("create introspector: %v", err)
	}
	certDir, roots := writeServingCert(t)
	port := freePort(t)
	server := ctrlwebhook.NewServer(ctrlwebhook.Options{Host: "127.0.0.1", Port: port, CertDir: certDir})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	registerEndpoints(ctx, server, logr.Discard(), config.NewWebhookServerConfig(), webhookDeps{introspector: introspector})

	s := &webhookServer{
		addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			ForceAttemptHTTP2: true,
		}},
		cancel:  cancel,
		stopped: make(chan error, 1),
	}
	go func() { s.stopped <- server.Start(ctx) }()
	waitUntilStarted(t, server)
	return s
}

type answer struct {
	resp *http.Response
	body []byte
	err  error
}

// postTokenReview sends one TokenReview in the background and returns where its
// answer arrives.
func postTokenReview(s *webhookServer) <-chan answer {
	answered := make(chan answer, 1)
	go func() {
		review, _ := json.Marshal(authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: "a.jwt.token"}})
		resp, err := s.client.Post("https://"+s.addr+tokenReviewEndpoint, "application/json", bytes.NewReader(review))
		if err != nil {
			answered <- answer{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var buf bytes.Buffer
		_, err = buf.ReadFrom(resp.Body)
		answered <- answer{resp: resp, body: buf.Bytes(), err: err}
	}()
	return answered
}

func assertZitadelsAnswer(t *testing.T, got answer) {
	t.Helper()
	if got.err != nil {
		t.Fatalf("the token check failed on the wire: %v", got.err)
	}
	if got.resp.ProtoMajor != 2 {
		t.Fatalf("the client spoke HTTP/%d, want HTTP/2 as Milo's API server does", got.resp.ProtoMajor)
	}
	var review authenticationv1.TokenReview
	if err := json.Unmarshal(got.body, &review); err != nil {
		t.Fatalf("decode TokenReview %q: %v", got.body, err)
	}
	if strings.Contains(review.Status.Error, "context canceled") {
		t.Fatalf("the shutdown cancelled the check in flight: status.error %q", review.Status.Error)
	}
	if !review.Status.Authenticated || review.Status.User.Username != "user@example.com" {
		t.Fatalf("want Zitadel's answer (authenticated as user@example.com), got %+v", review.Status)
	}
}

// receive returns the next value from ch, or fails the test after d.
func receive[T any](t *testing.T, ch <-chan T, d time.Duration, failure string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(d):
		t.Fatal(failure)
		var zero T
		return zero
	}
}

// writeApplicationKey writes a Zitadel application key with a real RSA key, so
// the introspector can sign its client assertion.
func writeApplicationKey(t *testing.T) string {
	t.Helper()
	_, keyPEM := newRSAKey(t)
	data, err := json.Marshal(map[string]string{
		"type": "application", "keyId": "test-key-id", "key": string(keyPEM), "clientId": "test-client-id",
	})
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return writeKey(t, "application-key.json", string(data))
}

// writeServingCert writes a throwaway self-signed certificate for 127.0.0.1 as
// tls.crt and tls.key, and returns the directory and a pool that trusts it.
func writeServingCert(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	key, keyPEM := newRSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "authn-webhook-test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	dir := t.TempDir()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
		t.Fatalf("write tls.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatalf("write tls.key: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return dir, roots
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// newRSAKey returns a throwaway RSA key and its PKCS#1 PEM.
func newRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func waitUntilStarted(t *testing.T, server ctrlwebhook.Server) {
	t.Helper()
	check := server.StartedChecker()
	waitFor(t, func() bool { return check(nil) == nil }, "the webhook server did not start")
}

func waitUntilListenerClosed(t *testing.T, addr string) {
	t.Helper()
	waitFor(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return true
		}
		_ = conn.Close()
		return false
	}, "the webhook server did not close its listener")
}

// waitFor polls done until it is true, or fails the test after 10 s.
func waitFor(t *testing.T, done func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal(failure)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
