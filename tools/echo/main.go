package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

func main() {
	mux := http.NewServeMux()

	// Simple health endpoint for readiness checks
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Echo endpoint:
	// - Only allows POST
	// - Limits body size to 1MB
	// - If body is valid JSON, returns it under {"echoed": <json>}
	// - Otherwise returns it as a string: {"echoed":"<body>"}
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		lr := io.LimitReader(r.Body, 1<<20) // 1MB cap for safety
		bodyBytes, err := io.ReadAll(lr)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		body := strings.TrimSpace(string(bodyBytes))

		w.Header().Set("Content-Type", "application/json")

		if body == "" {
			_, _ = w.Write([]byte(`{"echoed": null}`))
			return
		}

		if json.Valid([]byte(body)) {
			// Return raw JSON under the "echoed" key
			_, _ = w.Write([]byte(`{"echoed": `))
			_, _ = w.Write([]byte(body))
			_, _ = w.Write([]byte(`}`))
			return
		}

		// Not valid JSON: return as a JSON string
		escaped, _ := json.Marshal(body)
		_, _ = w.Write([]byte(`{"echoed": `))
		_, _ = w.Write(escaped)
		_, _ = w.Write([]byte(`}`))
	})

	log.Println("Echo tool listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", mux))
}
