package common_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openmeterio/openmeter/app/common"
	"github.com/openmeterio/openmeter/app/config"
	"github.com/openmeterio/openmeter/openmeter/app"
	secretentity "github.com/openmeterio/openmeter/openmeter/secret/entity"
)

func TestNewSecretServiceRequiresAnEncryptionKey(t *testing.T) {
	// given:
	// - a configuration without a secret encryption key
	// when:
	// - the secret service is built
	// then:
	// - it fails, so OpenMeter never stores app secrets in plaintext
	_, err := common.NewSecretService(config.SecretConfiguration{})
	require.Error(t, err)
}

func TestNewSecretServiceEncryptsSecrets(t *testing.T) {
	// given:
	// - a configuration with a valid secret encryption key
	// when:
	// - a secret is created through the service
	// then:
	// - the id that gets stored does not contain the value, and reads return it
	svc, err := common.NewSecretService(config.SecretConfiguration{EncryptionKey: strings.Repeat("ab", 32)})
	require.NoError(t, err)

	ctx := context.Background()
	appID := app.AppID{Namespace: "namespace", ID: "app-id"}
	id, err := svc.CreateAppSecret(ctx, secretentity.CreateAppSecretInput{AppID: appID, Key: "api_key", Value: "sk_test_value"})
	require.NoError(t, err)
	require.NotContains(t, id.ID, "sk_test_value")

	got, err := svc.GetAppSecret(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "sk_test_value", got.Value)
}
