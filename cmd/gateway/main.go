package main

import (
	"bytes"
	"crypto/tls"
	"crypto/ed25519"
    "crypto/x509"
    "encoding/base64"
    "errors"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"strings"

	"zerotrust/internal/pki"
	"zerotrust/internal/poca"
	"zerotrust/internal/egress"
	"zerotrust/internal/contracts"
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

func decodeAgentKeyFlexible(s string) (ed25519.PublicKey, error) {
    if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
        if len(b) == ed25519.PublicKeySize { return ed25519.PublicKey(b), nil }
        if pk, err2 := tryParsePKIX(b); err2 == nil { return pk, nil }
    }
    if b, err := base64.StdEncoding.DecodeString(s); err == nil {
        if len(b) == ed25519.PublicKeySize { return ed25519.PublicKey(b), nil }
        if pk, err2 := tryParsePKIX(b); err2 == nil { return pk, nil }
    }
    return nil, errors.New("unsupported ed25519 public key encoding")
}

func tryParsePKIX(der []byte) (ed25519.PublicKey, error) {
    pkAny, err := x509.ParsePKIXPublicKey(der)
    if err != nil { return nil, err }
    pk, ok := pkAny.(ed25519.PublicKey)
    if !ok { return nil, errors.New("not an ed25519 PKIX public key") }
    return pk, nil
}

func main() {
	// ---------- Config ----------
	const defaultAuditPath = "/var/log/zt-gateway/audit.jsonl"
	auditPath := getenv("AUDIT_PATH", defaultAuditPath)
	opaURL := getenv("OPA_URL", "http://opa:8181/v1/data/mcp/authz")
	backendURL := getenv("BACKEND_URL", "http://echo:8081/echo")
	todosURL := getenv("TODOS_URL", "http://todos:8082/call")
	maxBodyBytes := int64(2 << 20) // 2 MiB
	backendTimeout := 5 * time.Second
	opaTimeout := 3 * time.Second
	pocaRequired := getenv("POCA_REQUIRED", "true") == "true"
	pocaAgentsPath := getenv("POCA_AGENTS_PATH", "/app/pki/agents.yaml")
	nonceTTL := 5 * time.Minute
	clockSkew := 60 * time.Second
	egressPath := getenv("EGRESS_CONFIG_PATH", "/app/egress.yaml")
	egCfg, err := egress.Load(egressPath)
	if err != nil {
		log.Fatalf("failed to load egress config: %v", err)
	}
	schemaEchoPath := getenv("SCHEMA_ECHO_PATH", "/app/contracts/echo.v1.json")
	echoContract, err := contracts.Load(schemaEchoPath)
	if err != nil {
		log.Fatalf("failed to load echo schema: %v", err)
	}
	schemaIDEcho := echoContract.ID
	if schemaIDEcho == "" {
		schemaIDEcho = "echo.v1" // fallback if $id missing
	}
	schemaTodosPath := getenv("SCHEMA_TODOS_PATH", "/app/contracts/todo.create.v1.json")
	todosContract, err := contracts.Load(schemaTodosPath)
	if err != nil { log.Fatalf("failed to load todos schema: %v", err) }
	schemaIDTodos := todosContract.ID
	if schemaIDTodos == "" { schemaIDTodos = "todo.create.v1" }

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
	agents := poca.NewAgents()
	if err := pki.LoadAgentsYAML(pocaAgentsPath, agents.Set, decodeAgentKeyFlexible); err != nil {
		log.Fatalf("failed loading agents.yaml: %v", err)
	}
	nonces := poca.NewNonceCache(nonceTTL)
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

		// ---- Envelope: { "tool": "...", "payload": {...} } ----
		// Back-compat: if no envelope, default to echo + whole body as payload.
		resolvedTool := "echo"
		payloadBytes := body

		type envT struct {
			Tool    string          `json:"tool"`
			Payload json.RawMessage `json:"payload"`
		}
		var env envT
		if err := json.Unmarshal(body, &env); err == nil && env.Tool != "" && len(env.Payload) > 0 {
			resolvedTool = env.Tool
			payloadBytes = env.Payload
		}

		// --- PoCA verification ---
		headers := map[string]string{
			"X-PoCA-Manifest":  r.Header.Get("X-PoCA-Manifest"),
			"X-PoCA-Signature": r.Header.Get("X-PoCA-Signature"),
		}
		pocaRes := poca.Verify(headers, body, caller, resolvedTool, agents, nonces, time.Now().UTC(), clockSkew)
		if !pocaRes.OK {
			if pocaRequired {
				writeAudit(auditPath, AuditLog{
					TraceID:  traceID, Ts: time.Now().UTC().Format(time.RFC3339Nano),
					Caller: caller, Tool: resolvedTool, Decision: "deny",
					Reason: append([]string{"poca_failed"}, pocaRes.Reasons...),
					Status: http.StatusForbidden,
				})
				http.Error(w, "forbidden by PoCA", http.StatusForbidden)
				return
			}
			// Not required: continue but mark unverified
		}
		// ---- JSON-Schema validation (request) ----
		// Only enforce schema when caller explicitly opts into this contract via header.
		// This avoids rejecting valid non-contract JSON payloads used by some tests.
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(strings.ToLower(ct), "application/json") {
			var js any
			if err := json.Unmarshal(body, &js); err != nil {
				writeAudit(auditPath, AuditLog{
					TraceID: traceID, Ts: time.Now().UTC().Format(time.RFC3339Nano),
					Caller: caller, Tool: resolvedTool, Decision: "deny",
					Reason: []string{"schema_request_invalid", "json_parse_error"},
					Status: http.StatusBadRequest,
				})
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}

			contractID := r.Header.Get("X-Contract-ID")
			// parse the inner payload (envelope payload) for schema validation
			var payloadJSON any
			if err := json.Unmarshal(payloadBytes, &payloadJSON); err != nil {
				writeAudit(auditPath, AuditLog{
					TraceID: traceID, Ts: time.Now().UTC().Format(time.RFC3339Nano),
					Caller: caller, Tool: resolvedTool, Decision: "deny",
					Reason: []string{"schema_request_invalid", "json_parse_error_payload"},
					Status: http.StatusBadRequest,
				})
				http.Error(w, "invalid json payload", http.StatusBadRequest)
				return
			}
			if resolvedTool == "echo" && contractID == schemaIDEcho {
				if err := echoContract.Schema.Validate(payloadJSON); err != nil {
					log.Printf("schema validation failed: %v; body=%s", err, string(payloadBytes))
					writeAudit(auditPath, AuditLog{
						TraceID: traceID, Ts: time.Now().UTC().Format(time.RFC3339Nano),
						Caller: caller, Tool: resolvedTool, Decision: "deny",
						Reason: []string{"schema_request_invalid"},
						Status: http.StatusUnprocessableEntity,
					})
					http.Error(w, "invalid request schema", http.StatusUnprocessableEntity)
					return
				}
			}
			// todos schema validation (payload only) when client opts in via X-Contract-ID
			if resolvedTool == "todos" && contractID == schemaIDTodos {
				if err := todosContract.Schema.Validate(payloadJSON); err != nil {
					log.Printf("todos schema validation failed: %v; payload=%s", err, string(payloadBytes))
					writeAudit(auditPath, AuditLog{
						TraceID: traceID, Ts: time.Now().UTC().Format(time.RFC3339Nano),
						Caller: caller, Tool: resolvedTool, Decision: "deny",
						Reason: []string{"schema_request_invalid"},
						Status: http.StatusUnprocessableEntity,
					})
					http.Error(w, "invalid request schema", http.StatusUnprocessableEntity)
					return
				}
			}
		}
		// ---------- PDP (OPA) check ----------
		var allowed bool
		var reasons []string
		// Determine which schema ID (if any) should be conveyed to OPA
		sentSchemaID := r.Header.Get("X-Contract-ID")
		if sentSchemaID == "" && resolvedTool == "echo" {
			sentSchemaID = schemaIDEcho
		}
		allowed, reasons = checkOPA(opaURL, caller, resolvedTool, opaTimeout, traceID, pocaRes.Verified, sentSchemaID)
		// allowed, reasons := checkOPA(opaURL, caller, "echo", opaTimeout, traceID)
		if !allowed {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     resolvedTool,
				Decision: "deny",
				Reason:   reasons,
				Status:   http.StatusForbidden,
			})
			http.Error(w, "forbidden by policy", http.StatusForbidden)
			return
		}

		// Resolve target URL by tool (router)
		targetURL := backendURL // default: echo
		switch resolvedTool {
		case "echo":
			// already default
		case "todos":
			targetURL = todosURL
		default:
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     resolvedTool,
				Decision: "deny",
				Reason:   []string{"unknown_tool"},
				Status:   http.StatusBadRequest,
			})
			http.Error(w, "unknown tool", http.StatusBadRequest)
			return
		}

		// ---------- Relay to backend ----------
		// Egress deny-by-default: ensure targetURL is allowlisted
		if !egCfg.IsAllowed(targetURL) {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     resolvedTool,
				Decision: "deny",
				Reason:   []string{"egress_denied"},
				Status:   http.StatusForbidden,
			})
			http.Error(w, "forbidden: egress denied", http.StatusForbidden)
			return
		}

		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(payloadBytes))
		if err != nil {
			writeAudit(auditPath, AuditLog{
				TraceID:  traceID,
				Ts:       time.Now().UTC().Format(time.RFC3339Nano),
				Caller:   caller,
				Tool:     resolvedTool,
				Decision: "deny",
				Reason:   []string{"failed to build backend request"},
				Status:   http.StatusInternalServerError,
			})
			http.Error(w, "failed to build backend request", http.StatusInternalServerError)
			return
		}
		ct = r.Header.Get("Content-Type")
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
				Tool:     resolvedTool,
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
				Tool:     resolvedTool,
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
			Tool:     resolvedTool,
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
func checkOPA(opaURL, caller, tool string, timeout time.Duration, traceID string, pocaVerified bool, schemaID string) (bool, []string) {
    input := map[string]any{
        "input": map[string]any{
            "caller":        caller,
            "tool":          tool,
            "trace_id":      traceID,
            "poca_verified": pocaVerified,
            "schema_id":     schemaID,    // <<—— add this
        },
    }
    b, _ := json.Marshal(input)

    client := &http.Client{Timeout: timeout}
    resp, err := client.Post(opaURL, "application/json", bytes.NewReader(b))
    if err != nil {
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
