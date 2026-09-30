package msauth

import (
	"regexp"
	"strings"
)

// Client describes one public client application this build may authenticate
// as. A public client has no secret; the ID identifies the application only.
type Client struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	// Broker reports whether the client can use the operating-system broker.
	Broker bool `json:"broker,omitempty"`
	// DefaultPolicy is the acquisition policy used when a request does not
	// name one. Config.normalized derives it from Broker when left empty.
	DefaultPolicy Policy `json:"defaultPolicy,omitempty"`
}

// guidPattern recognizes a bare application ID so a caller can name a client
// this build has never heard of without first writing a config file.
var guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// LookupClient resolves a client by configured name or by application ID. An
// unconfigured but well-formed application ID resolves to an ad-hoc broker
// client, which is what lets a caller use their own registration without
// changing this package or writing a config file.
func (c Config) LookupClient(name string) (Client, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Client{}, false
	}
	for _, client := range c.Clients {
		if strings.EqualFold(client.Name, name) || strings.EqualFold(client.ID, name) {
			return client, true
		}
	}
	if guidPattern.MatchString(name) {
		return Client{
			Name:          name,
			ID:            name,
			Description:   "ad-hoc application id supplied by the caller",
			Broker:        true,
			DefaultPolicy: PolicyWAMFirst,
		}, true
	}
	return Client{}, false
}

// ClientList returns a copy of the configured clients.
func (c Config) ClientList() []Client {
	out := make([]Client, len(c.Clients))
	copy(out, c.Clients)
	return out
}

// ClientNames returns the configured client names in configuration order.
func (c Config) ClientNames() []string {
	names := make([]string, 0, len(c.Clients))
	for _, client := range c.Clients {
		names = append(names, client.Name)
	}
	return names
}

// Clients returns the clients from the effective configuration. A configuration
// that cannot be resolved reports the built-in defaults, so a listing command
// still explains what this build ships with; DescribeConfig carries the error.
func Clients() []Client {
	return effectiveConfig().ClientList()
}

// LookupClient resolves a client against the effective configuration.
func LookupClient(name string) (Client, bool) {
	config, err := LoadConfig()
	if err != nil {
		return Client{}, false
	}
	return config.LookupClient(name)
}
