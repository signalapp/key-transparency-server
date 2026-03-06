//
// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/signalapp/keytransparency/crypto/vrf"
	edvrf "github.com/signalapp/keytransparency/crypto/vrf/ed25519"
	"github.com/signalapp/keytransparency/db"
	"github.com/signalapp/keytransparency/tree/transparency"

	"gopkg.in/yaml.v2"
)

// envstr is a string in the YAML config file that expands environment variables
// when parsed.
type envstr string

func (es *envstr) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*es = envstr(os.ExpandEnv(s))
	return nil
}

func (es envstr) String() string { return string(es) }

// Config specifies the file format of config files.
type Config struct {
	KtServiceConfig      *ServiceConfig `yaml:"kt"`
	KtQueryServiceConfig *ServiceConfig `yaml:"kt-query"`
	KtTestServiceConfig  *ServiceConfig `yaml:"kt-test"`

	LogOutputFile string `yaml:"log-output"`
	MetricsAddr   string `yaml:"metrics-addr"`
	OtlpEnabled   bool   `yaml:"otlp-enabled"` // Whether to configure OpenTelemetry Metrics
	HealthAddr    string `yaml:"health-addr"`

	APIConfig      *APIConfig      `yaml:"api"`
	StreamConfig   *StreamConfig   `yaml:"stream"`
	DatabaseConfig *DatabaseConfig `yaml:"db"`
	AccountDB      string          `yaml:"account-db"`
	CacheConfig    *CacheConfig    `yaml:"cache"`
}

type CacheConfig struct {
	PrefixSize int `yaml:"prefix-size"`
	LogSize    int `yaml:"log-size"`
	TopSize    int `yaml:"top-size"`
}

type ServiceConfig struct {
	ServerAddr string `yaml:"server-addr"`
	// a map of headers to a list of authorized values. at least one header to value mapping must be present on client requests
	AuthorizedHeaders map[string][]string `yaml:"authorized-headers"`
	// a map of header values to auditor name. each key in this map should match a value in the AuthorizedHeaders map.
	HeaderValueToAuditorName map[string]string `yaml:"header-value-to-auditor-name"`
}

type APIConfig struct {
	SigningKey envstr `yaml:"signing-key"` // 32 byte hex-encoded seed for the signing private key.
	signingKey ed25519.PrivateKey

	VRFKey envstr `yaml:"vrf-key"` // PEM encoded VRF private key.
	vrfKey vrf.PrivateKey

	PrefixAesKey envstr `yaml:"prefix-key"` // 32 random hex-encoded bytes.
	prefixAesKey []byte

	OpeningKey envstr `yaml:"opening-key"` // 32 random hex-encoded bytes.
	openingKey []byte

	FakeUpdates *FakeUpdates `yaml:"fake"`

	// A map of auditor name to its hex-encoded public signature key.
	AuditorConfigs map[string]string `yaml:"auditors"`
	auditorConfigs map[string]ed25519.PublicKey

	Distinguished time.Duration `yaml:"distinguished"`

	// Minimum latency for a search request
	MinimumSearchDelay time.Duration `yaml:"min-search-delay"`
	// Minimum latency for a monitor request
	MinimumMonitorDelay time.Duration `yaml:"min-monitor-delay"`
	// What percent of the minimum delay to use for determining the jitter range
	JitterPercent int `yaml:"jitter-percent"`
}

func (config *APIConfig) TreeConfig() *transparency.PrivateConfig {
	mode := transparency.ContactMonitoring
	if config.auditorConfigs != nil {
		mode = transparency.ThirdPartyAuditing
	}
	return &transparency.PrivateConfig{
		Mode:         mode,
		SigKey:       config.signingKey,
		AuditorKeys:  config.auditorConfigs,
		VrfKey:       config.vrfKey,
		PrefixAesKey: config.prefixAesKey,
		OpeningKey:   config.openingKey,
	}
}

func (config *APIConfig) NewTree(tx db.TransparencyStore) (*transparency.Tree, error) {
	return transparency.NewTree(config.TreeConfig(), tx)
}

// FakeUpdates specifies how often to make fake updates. Updates are made such
// that there are `count` updates total every `interval` of time.
type FakeUpdates struct {
	Count    int           `yaml:"count"`
	Interval time.Duration `yaml:"interval"`
}

type StreamConfig struct {
	AciStreamName      envstr `yaml:"aci-stream-name"`
	E164StreamName     envstr `yaml:"e164-stream-name"`
	UsernameStreamName envstr `yaml:"username-stream-name"`

	NewStreams []string `yaml:"new-streams"`

	// If TableName is not provided, backfill will not be attempted.
	TableName envstr `yaml:"table"`
}

type DatabaseConfig struct {
	// LevelDB
	File string `yaml:"file"`

	// DynamoDB
	Table    envstr `yaml:"table"`
	Parallel int    `yaml:"parallel"`
}

func (config *DatabaseConfig) Validate() error {
	if config == nil {
		return fmt.Errorf("field not provided: db")
	}

	level := config.File != ""
	dynamo := config.Table != "" && config.Parallel != 0

	if !level && !dynamo {
		return fmt.Errorf("no database connection information provided")
	} else if level && dynamo {
		return fmt.Errorf("can not provide both leveldb and dynamodb connections")
	}
	return nil
}

func (config *DatabaseConfig) Connect() (db.TransparencyStore, error) {
	if config.File != "" {
		return db.NewLDBTransparencyStore(config.File)
	}
	return db.NewDynamoDBTransparencyStore(config.Table.String(), config.Parallel)
}

func (c *Config) ConnectAccountDB() (db.AccountDB, error) {
	if c.AccountDB == "mock" {
		return &db.MockAccountDB{}, nil
	}
	return db.NewAccountDB(c.AccountDB)
}

func Read(filename string) (*Config, error) {
	// Read from file and parse.
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var parsed Config
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	// Check that all required fields are populated.
	if parsed.KtQueryServiceConfig != nil {
		if parsed.KtQueryServiceConfig.ServerAddr == "" {
			return nil, fmt.Errorf("field not provided for service kt-query: server-addr")
		}
		if parsed.APIConfig.MinimumSearchDelay == 0 {
			return nil, fmt.Errorf("field not provided for service kt-query: min-search-delay")
		}
		if parsed.APIConfig.MinimumMonitorDelay == 0 {
			return nil, fmt.Errorf("field not provided for service kt-query: min-monitor-delay")
		}
	}

	if parsed.KtServiceConfig != nil {
		if parsed.KtServiceConfig.ServerAddr == "" {
			return nil, fmt.Errorf("field not provided for service kt: server-addr")
		}
		if parsed.KtServiceConfig.AuthorizedHeaders == nil || len(parsed.KtServiceConfig.AuthorizedHeaders) == 0 {
			return nil, fmt.Errorf("field not provided for service kt: authorized-headers")
		}
		if parsed.KtServiceConfig.HeaderValueToAuditorName == nil || len(parsed.KtServiceConfig.HeaderValueToAuditorName) == 0 {
			return nil, fmt.Errorf("field not provided for service kt: header-value-to-auditor-name")
		}
		if parsed.APIConfig.AuditorConfigs == nil || len(parsed.APIConfig.AuditorConfigs) == 0 {
			return nil, fmt.Errorf("field not provided for service kt: auditors")
		}
		// Ensure every header value maps to an auditor name
		for _, values := range parsed.KtServiceConfig.AuthorizedHeaders {
			for _, value := range values {
				if len(parsed.KtServiceConfig.HeaderValueToAuditorName[value]) == 0 {
					return nil, fmt.Errorf("header value %s has no associated auditor name", value)
				}
			}
		}
		// Ensure every auditor name maps to a public key
		for _, auditorName := range parsed.KtServiceConfig.HeaderValueToAuditorName {
			if len(parsed.APIConfig.AuditorConfigs[auditorName]) == 0 {
				return nil, fmt.Errorf("auditor %s has no associated public key", auditorName)
			}
		}
		if parsed.APIConfig.Distinguished == 0 {
			return nil, fmt.Errorf("field not provided for service kt: distinguished")
		}
	}

	if parsed.KtTestServiceConfig != nil {
		if parsed.KtTestServiceConfig.ServerAddr == "" {
			return nil, fmt.Errorf("field not provided for service kt-test: server-addr")
		}
	}

	if parsed.KtServiceConfig == nil && parsed.KtQueryServiceConfig == nil && parsed.KtTestServiceConfig == nil {
		return nil, fmt.Errorf("at least one server-addr field must be provided")
	} else if parsed.MetricsAddr == "" {
		return nil, fmt.Errorf("field not provided: metrics-addr")
	} else if parsed.HealthAddr == "" {
		return nil, fmt.Errorf("field not provided: health-addr")
	} else if parsed.APIConfig == nil {
		return nil, fmt.Errorf("field not provided: api")
	} else if parsed.APIConfig.SigningKey == "" {
		return nil, fmt.Errorf("field not provided: api.signing-key")
	} else if parsed.APIConfig.VRFKey == "" {
		return nil, fmt.Errorf("field not provided: api.vrf-key")
	} else if parsed.APIConfig.PrefixAesKey == "" {
		return nil, fmt.Errorf("field not provided: api.prefix-key")
	} else if parsed.APIConfig.OpeningKey == "" {
		return nil, fmt.Errorf("field not provided: api.opening-key")
	} else if err := parsed.DatabaseConfig.Validate(); err != nil {
		return nil, err
	}

	if parsed.APIConfig.FakeUpdates != nil {
		if parsed.APIConfig.FakeUpdates.Count == 0 {
			return nil, fmt.Errorf("field not provided: api.fake.count")
		} else if parsed.APIConfig.FakeUpdates.Interval == 0 {
			return nil, fmt.Errorf("field not provided: api.fake.interval")
		}
	}

	if parsed.StreamConfig != nil {
		if parsed.StreamConfig.AciStreamName == "" {
			return nil, fmt.Errorf("field not provided: stream.aci-stream-name")
		}
		if parsed.StreamConfig.E164StreamName == "" {
			return nil, fmt.Errorf("field not provided: stream.e164-stream-name")
		}
		if parsed.StreamConfig.UsernameStreamName == "" {
			return nil, fmt.Errorf("field not provided: stream.username-stream-name")
		}
	}

	if parsed.APIConfig.JitterPercent < 0 || parsed.APIConfig.JitterPercent > 100 {
		return nil, fmt.Errorf("jitter percent must be between 0 and 100")
	}

	// Parse cryptographic keys.
	seed, err := hex.DecodeString(parsed.APIConfig.SigningKey.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %v", err)
	} else if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key is wrong size: wanted=%v, got=%v", ed25519.SeedSize, len(seed))
	}
	parsed.APIConfig.signingKey = ed25519.NewKeyFromSeed(seed)

	vrfKey, err := hex.DecodeString(parsed.APIConfig.VRFKey.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse vrf key: %v", err)
	}
	parsed.APIConfig.vrfKey, err = edvrf.NewVRFSigner(vrfKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vrf key: %v", err)
	}

	prefixAesKey, err := hex.DecodeString(parsed.APIConfig.PrefixAesKey.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parsed prefix seed: %v", err)
	} else if len(prefixAesKey) != 32 {
		return nil, fmt.Errorf("prefix AES key is wrong size: wanted=%v, got=%v", 32, len(prefixAesKey))
	}
	parsed.APIConfig.prefixAesKey = prefixAesKey

	openingKey, err := hex.DecodeString(parsed.APIConfig.OpeningKey.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parsed opening key: %v", err)
	} else if len(openingKey) != 32 {
		return nil, fmt.Errorf("opening key is wrong size: wanted=%v, got=%v", 32, len(openingKey))
	}
	parsed.APIConfig.openingKey = openingKey

	parsed.APIConfig.auditorConfigs = map[string]ed25519.PublicKey{}
	for auditorName, publicKey := range parsed.APIConfig.AuditorConfigs {
		pubKey, err := hex.DecodeString(publicKey)

		if err != nil {
			return nil, fmt.Errorf("failed to parse auditor public key: %v for auditor %s", err, auditorName)
		} else if len(pubKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("auditor public key is wrong size: wanted=%v, got=%v for auditor %s", ed25519.PublicKeySize, len(pubKey), auditorName)
		}
		parsed.APIConfig.auditorConfigs[auditorName] = pubKey
	}

	// If unspecified, use default cache sizes
	if parsed.CacheConfig == nil {
		parsed.CacheConfig = &CacheConfig{
			PrefixSize: 20000,
			LogSize:    2000,
			TopSize:    2000,
		}
	}

	if parsed.CacheConfig.PrefixSize == 0 {
		parsed.CacheConfig.PrefixSize = 20000
	}

	if parsed.CacheConfig.LogSize == 0 {
		parsed.CacheConfig.LogSize = 2000
	}

	if parsed.CacheConfig.TopSize == 0 {
		parsed.CacheConfig.TopSize = 2000
	}

	return &parsed, nil
}

func (c *Config) SetLogOutput() error {
	if c.LogOutputFile != "" {
		f, err := os.OpenFile(c.LogOutputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("Failed to open log file: %v", err)
		}
		log.Default().SetOutput(io.MultiWriter(os.Stderr, f))
		go func() {
			for range time.Tick(time.Second) {
				f.Sync()
			}
		}()
		return nil
	}
	return nil
}
