package egress

import (
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type Config struct {
	Default string `yaml:"default"` // "deny" or "allow"
	Allow   []Rule `yaml:"allow"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) IsAllowed(target string) bool {
	tu, err := url.Parse(target)
	if err != nil {
		// malformed target -> deny unless default allow (we prefer fail-closed)
		return strings.EqualFold(c.Default, "allow")
	}
	t := normalized(tu)
	for _, r := range c.Allow {
		ru, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		if normalized(ru) == t {
			return true
		}
	}
	return strings.EqualFold(c.Default, "allow")
}

func normalized(u *url.URL) string {
	// exact compare: scheme://host[:port]/path
	// (query/fragment not considered for allowlist)
	host := strings.ToLower(u.Host)
	scheme := strings.ToLower(u.Scheme)
	path := u.Path
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}