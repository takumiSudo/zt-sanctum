package main
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"
)
var b64url = base64.RawURLEncoding
func main() {
	keyPath := flag.String("key", "pki/agent.key", "Ed25519 private key PEM")
	caller := flag.String("caller", "agent", "caller_id")
	tool := flag.String("tool", "echo", "tool")
	intent := flag.String("intent", "echo_payload", "intent")
	expMin := flag.Int("expmin", 5, "expiry minutes from now")
	body := flag.String("body", `{"message":"hello gateway"}`, "payload body")
	flag.Parse()

	// load ed25519 private key
	pemBytes, _ := os.ReadFile(*keyPath)
	block, _ := pem.Decode(pemBytes)
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil { panic(err) }
	priv := privAny.(ed25519.PrivateKey)

	// payload hash
	h := sha256.Sum256([]byte(*body))
	man := map[string]any{
		"ver":"poca-1",
		"caller_id":*caller,
		"tool":*tool,
		"intent":*intent,
		"scopes":[]string{"read"},
		"payload_sha256": hex.EncodeToString(h[:]),
		"nonce": hex.EncodeToString(h[:8]), // quick demo nonce
		"exp": time.Now().UTC().Add(time.Duration(*expMin)*time.Minute).Format(time.RFC3339),
	}
	js, _ := json.Marshal(man)
	m64 := b64url.EncodeToString(js)
	sig := ed25519.Sign(priv, []byte(m64))
	s64 := b64url.EncodeToString(sig)

	fmt.Println("X-PoCA-Manifest:", m64)
	fmt.Println("X-PoCA-Signature:", s64)
	fmt.Println("Body:", *body)
}