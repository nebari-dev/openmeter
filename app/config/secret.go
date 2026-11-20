package config

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/viper"

	secretadapter "github.com/openmeterio/openmeter/openmeter/secret/adapter"
)

// SecretConfiguration configures how app secrets (such as Stripe API keys) are stored.
type SecretConfiguration struct {
	// EncryptionKey is the hex encoded 32-byte key app secrets are encrypted with before they are stored.
	EncryptionKey string `mapstructure:"encryptionKey"`
}

// Key returns the decoded encryption key.
func (c SecretConfiguration) Key() ([]byte, error) {
	key, err := hex.DecodeString(c.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encryption key is not valid hex: %w", err)
	}

	return key, nil
}

// Validate validates the configuration. An empty key is valid: only processes
// that read or write app secrets require one, when they build the secret service.
func (c SecretConfiguration) Validate() error {
	if c.EncryptionKey == "" {
		return nil
	}

	key, err := c.Key()
	if err != nil {
		return err
	}

	if len(key) != secretadapter.KeySize {
		return fmt.Errorf("encryption key must be %d bytes, got %d", secretadapter.KeySize, len(key))
	}

	return nil
}

// ConfigureSecret configures some defaults in the Viper instance.
func ConfigureSecret(v *viper.Viper) {
	v.SetDefault("secret.encryptionKey", "")
}
