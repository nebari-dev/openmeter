package common

import (
	"errors"

	"github.com/google/wire"

	"github.com/openmeterio/openmeter/app/config"
	appstripe "github.com/openmeterio/openmeter/openmeter/app/stripe"
	"github.com/openmeterio/openmeter/openmeter/secret"
	secretadapter "github.com/openmeterio/openmeter/openmeter/secret/adapter"
	secretservice "github.com/openmeterio/openmeter/openmeter/secret/service"
)

var Secret = wire.NewSet(
	wire.Bind(new(secret.Service), new(*secretservice.Service)),
	wire.Bind(new(appstripe.WebhookSecretService), new(*secretservice.Service)),

	NewSecretService,
)

// NewSecretService returns the secret service, which encrypts app secrets with
// the configured key before they are stored. It fails without a key, so app
// secrets are never stored in plaintext.
func NewSecretService(conf config.SecretConfiguration) (*secretservice.Service, error) {
	if conf.EncryptionKey == "" {
		return nil, errors.New("secret encryption key is required (secret.encryptionKey, env SECRET_ENCRYPTIONKEY)")
	}

	key, err := conf.Key()
	if err != nil {
		return nil, err
	}

	secretAdapter, err := secretadapter.NewEncrypted(key)
	if err != nil {
		return nil, err
	}

	return secretservice.New(secretservice.Config{
		Adapter: secretAdapter,
	})
}
