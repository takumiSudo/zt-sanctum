package poca

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var b64url = base64.RawURLEncoding

type Manifest struct {
	Ver           string   `json:"ver"`
	CallerID      string   `json:"caller_id"`
	Tool          string   `json:"tool"`
	Intent        string   `json:"intent"`
	Scopes        []string `json:"scopes"`
	PayloadSHA256 string   `json:"payload_sha256"` // hex
	Nonce         string   `json:"nonce"`
	Exp           string   `json:"exp"`            // RFC3339
}

type Agents struct {
	mu  sync.RWMutex
	key map[string]ed25519.PublicKey // caller_id -> pubkey
}

func NewAgents() *Agents { return &Agents{key: map[string]ed25519.PublicKey{}} }
func (a *Agents) Set(caller string, pk ed25519.PublicKey) { a.mu.Lock(); a.key[caller]=pk; a.mu.Unlock() }
func (a *Agents) Get(caller string) (ed25519.PublicKey, bool) { a.mu.RLock(); pk, ok := a.key[caller]; a.mu.RUnlock(); return pk, ok }

type NonceCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[string]time.Time
}
func NewNonceCache(ttl time.Duration) *NonceCache { return &NonceCache{ttl: ttl, data: map[string]time.Time{}} }
func (c *NonceCache) Seen(n string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// evict old
	for k,t := range c.data {
		if now.Sub(t) > c.ttl { delete(c.data, k) }
	}
	if _, ok := c.data[n]; ok { return true }
	c.data[n] = now
	return false
}

type Result struct {
	OK         bool
	Reasons    []string
	Manifest   *Manifest
	Verified   bool
}

func Verify(headers map[string]string, body []byte, callerCN string, expectedTool string, agents *Agents, nonces *NonceCache, now time.Time, clockSkew time.Duration) Result {
	res := Result{OK:false, Verified:false}
	m64, ok1 := headers["X-PoCA-Manifest"]
	s64, ok2 := headers["X-PoCA-Signature"]
	if !ok1 || !ok2 {
		res.Reasons = append(res.Reasons, "poca_missing_headers")
		return res
	}
	manBytes, err := b64url.DecodeString(m64)
	if err != nil {
		res.Reasons = append(res.Reasons, "poca_manifest_b64_decode")
		return res
	}
	var man Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		res.Reasons = append(res.Reasons, "poca_manifest_json")
		return res
	}
	// Basic fields
	if man.CallerID == "" || man.Tool == "" || man.PayloadSHA256 == "" || man.Nonce == "" || man.Exp == "" {
		res.Reasons = append(res.Reasons, "poca_manifest_missing_fields")
		return res
	}
	// Caller consistency
	if man.CallerID != callerCN {
		res.Reasons = append(res.Reasons, "poca_caller_mismatch")
		return res
	}
	// Tool consistency (for now, gateway routes only to echo)
	if man.Tool != expectedTool {
		res.Reasons = append(res.Reasons, "poca_tool_mismatch")
		return res
	}
	// Expiry
	exp, err := time.Parse(time.RFC3339, man.Exp)
	if err != nil {
		res.Reasons = append(res.Reasons, "poca_exp_parse")
		return res
	}
	if now.Add(-clockSkew).After(exp) {
		res.Reasons = append(res.Reasons, "poca_expired")
		return res
	}
	// Nonce replay
	if nonces != nil && nonces.Seen(man.Nonce, now) {
		res.Reasons = append(res.Reasons, "poca_replay")
		return res
	}
	// Payload hash
	h := sha256.Sum256(body)
	if hex.EncodeToString(h[:]) != man.PayloadSHA256 {
		res.Reasons = append(res.Reasons, "poca_payload_hash_mismatch")
		return res
	}
	// Signature
	sig, err := b64url.DecodeString(s64)
	if err != nil {
		res.Reasons = append(res.Reasons, "poca_sig_b64_decode")
		return res
	}
	pk, ok := agents.Get(man.CallerID)
	if !ok {
		res.Reasons = append(res.Reasons, "poca_unknown_caller_pubkey")
		return res
	}
	// Sign over the EXACT base64url manifest string (m64 bytes)
	if !ed25519.Verify(pk, []byte(m64), sig) {
		res.Reasons = append(res.Reasons, "poca_sig_invalid")
		return res
	}
	res.OK = true
	res.Verified = true
	res.Manifest = &man
	return res
}

func LoadEd25519PubkeyB64(s string) (ed25519.PublicKey, error) {
	raw, err := b64url.DecodeString(s)
	if err != nil { return nil, err }
	if l := len(raw); l != ed25519.PublicKeySize { return nil, errors.New("bad pubkey size") }
	pk := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	copy(pk, raw)
	return pk, nil
}