package pki

import (
	"crypto/ed25519"
	"os"

	"gopkg.in/yaml.v3"
)

type fileAgents struct {
	Agents map[string]struct{
		Ed25519PubkeyB64 string `yaml:"ed25519_pubkey_b64"`
	} `yaml:"agents"`
}

func LoadAgentsYAML(path string, set func(caller string, pk ed25519.PublicKey), decodePub func(string)(ed25519.PublicKey,error)) error {
	b, err := os.ReadFile(path)
	if err != nil { return err }
	var fa fileAgents
	if err := yaml.Unmarshal(b, &fa); err != nil { return err }
	for caller, v := range fa.Agents {
		pk, err := decodePub(v.Ed25519PubkeyB64)
		if err != nil { return err }
		set(caller, pk)
	}
	return nil
}