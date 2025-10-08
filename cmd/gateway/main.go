package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"gopkg.in/yaml.v3" // (indirect through pki package fetch)
	"zerotrust/internal/pki"
	"zerotrust/internal/poca"
)

type AuditLog struct {
	TraceID  string   `json:"trace_id"`
	Ts       string   `json:"ts"`
	Caller   string   `json:"caller"`
	Tool     string   `json:"tool"`
	Decision string   `json:"decision"`
	Reason   []string `json:"reason,omitempty"`
	Status   int      `json:"status"`
}

func main() {
	// ---------- Config ----------
	const defaultAuditPath = "/var/log/zt-gateway/audit.jsonl"
	auditPath := getenv("AUDIT_PATH", defaultAuditPath)
	opaURL := getenv("OPA_URL", "http://opa:8181/v1/data/mcp/authz")
	backendURL := getenv("BACKEND_URL", "http://echo:8081/echo")
	maxBodyBytes := int64(2 << 20) // 2 MiB
	backendTimeout := 5 * time.Second
	opaTimeout := 3 * time.Second
	pocaRequired := getenv("POCA_REQUIRED", "true") == "true"
	pocaAgentsPath := getenv("POCA_AGENTS_PATH", "/app/pki/agents.yaml")
	nonceTTL := 5 * time.Minute
	clockSkew := 60 * time.Second

	// ---------- mTLS trust (client auth) ----------
	caCert, err := os.ReadFile("/certs/ca.crt")
	if err != nil {
		log.Fatalf("failed to read ca cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	// ---------- HTTP mux ----------
	mux := http.NewServeMux()

	// 1) Health endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 2) Relay endpoint (PEP)
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		traceID := newTraceID()

		// Defensive: require verified client cert
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   "",
				Tool:     "echo",
				Decision: "deny",
				Reason:   []string{"missing client certificate"},
				Status:   http.StatusUnauthorized,
			})
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		caller := cert.Subject.CommonName

		// Max request size guard
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		// Read inbound body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     "echo",
				Decision: "deny",
				Reason:   []string{"failed to read request body"},
				Status:   http.StatusBadRequest,
			})
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		// ---------- PDP (OPA) check ----------
		allowed, reasons := checkOPA(opaURL, caller, "echo", opaTimeout, traceID)
		if !allowed {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     "echo",
				Decision: "deny",
				Reason:   reasons,
				Status:   http.StatusForbidden,
			})
			http.Error(w, "forbidden by policy", http.StatusForbidden)
			return
		}

		// ---------- Relay to backend ----------
		req, err := http.NewRequest(http.MethodPost, backendURL, bytes.NewReader(body))
		if err != nil {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     "echo",
				Decision: "deny",
				Reason:   []string{"failed to build backend request"},
				Status:   http.StatusInternalServerError,
			})
			http.Error(w, "failed to build backend request", http.StatusInternalServerError)
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)

		client := &http.Client{Timeout: backendTimeout}
		resp, err := client.Do(req)
		if err != nil {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     "echo",
				Decision: "deny",
				Reason:   []string{"backend error"},
				Status:   http.StatusBadGateway,
			})
			http.Error(w, "backend error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     "echo",
				Decision: "deny",
				Reason:   []string{"failed to read backend response"},
				Status:   http.StatusBadGateway,
			})
			http.Error(w, "failed to read backend response", http.StatusBadGateway)
			return
		}

		// Success audit
		writeAudit(auditPath, AuditLog{
			TraceID:  traceID,
			Ts:       time.Now().UTC().Format(time.RFC3339Nano),
			Caller:   caller,
			Tool:     "echo",
			Decision: "allow",
			Status:   resp.StatusCode,
		})

		// Propagate response
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	})

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   mux,
		// Optional: reasonable timeouts on the server side
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("ZT MCP Gateway listening on :8443")
	log.Fatal(server.ListenAndServeTLS("/certs/server.crt", "/certs/server.key"))
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// checkOPA calls the OPA data API and returns (allowed, reasons)
func checkOPA(opaURL, caller, tool string, timeout time.Duration, traceID string) (bool, []string) {
	input := map[string]any{
		"input": map[string]any{
			"caller": caller,
			"tool":   tool,
			// you can enrich this later (env, fields, schema_id, etc.)
			"trace_id": traceID,
		},
	}
	b, _ := json.Marshal(input)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(opaURL, "application/json", bytes.NewReader(b))
	if err != nil {
		// Fail closed on OPA errors
		return false, []string{"opa_unreachable"}
	}
	defer resp.Body.Close()

	var out struct {
		Result struct {
			Allow  bool     `json:"allow"`
			Reason []string `json:"reason"`
		} `json:"result"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &out); err != nil {
		return false, []string{"opa_bad_response"}
	}
	return out.Result.Allow, out.Result.Reason
}

// newTraceID returns a 16-byte hex string
func newTraceID() string {
	var b [16]byte
	// best-effort randomness from /dev/urandom
	f, err := os.Open("/dev/urandom")
	if err != nil {
		ts := time.Now().UnixNano()
		return hex.EncodeToString([]byte(fmt.Sprintf("%x", ts)))
	}
	defer f.Close()
	_, _ = io.ReadFull(f, b[:])
	return hex.EncodeToString(b[:])
}

// writeAudit appends a JSON line to the audit file and also prints to stdout
func writeAudit(path string, rec AuditLog) {
	// Ensure directory exists
	_ = os.MkdirAll(filepath.Dir(path), 0o755)

	// Marshal JSON
	line, err := json.Marshal(rec)
	if err != nil {
		fmt.Println(`{"error":"audit_marshal_failed"}`)
		return
	}

	// Append to file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}

	// Also to stdout for convenience
	fmt.Println(string(line))
}
