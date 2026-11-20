package adapter

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openmeterio/openmeter/openmeter/app"
	secretentity "github.com/openmeterio/openmeter/openmeter/secret/entity"
)

func testEncryptionKey(b byte) []byte {
	return bytes.Repeat([]byte{b}, 32)
}

func TestEncryptedAdapterRoundTripsWithoutStoringTheValue(t *testing.T) {
	// given:
	// - an encrypting adapter
	// when:
	// - a secret is created and then read back by the returned id
	// then:
	// - the read returns the original value and the id does not contain it
	ctx := context.Background()
	a, err := NewEncrypted(testEncryptionKey(1))
	require.NoError(t, err)

	appID := app.AppID{Namespace: "namespace", ID: "app-id"}
	value := "sk_test_value"

	id, err := a.CreateAppSecret(ctx, secretentity.CreateAppSecretInput{AppID: appID, Key: "api_key", Value: value})
	require.NoError(t, err)
	require.NotContains(t, id.ID, value)

	got, err := a.GetAppSecret(ctx, id)
	require.NoError(t, err)
	require.Equal(t, value, got.Value)
}

func TestEncryptedAdapterReadsSecretsStoredBeforeEncryption(t *testing.T) {
	// given:
	// - a secret id written by the plaintext adapter, whose id is the value
	// when:
	// - the encrypting adapter reads it
	// then:
	// - the value is returned as is, so existing apps keep working
	a, err := NewEncrypted(testEncryptionKey(1))
	require.NoError(t, err)

	id := secretentity.NewSecretID(app.AppID{Namespace: "namespace", ID: "app-id"}, "sk_test_legacy", "api_key")

	got, err := a.GetAppSecret(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, "sk_test_legacy", got.Value)
}

func TestEncryptedAdapterRejectsCiphertextMovedToAnotherSecret(t *testing.T) {
	// given:
	// - a secret encrypted for one app's api key
	// when:
	// - its stored id is read as another app's secret or as a different key
	// then:
	// - decryption fails instead of returning the value
	ctx := context.Background()
	a, err := NewEncrypted(testEncryptionKey(1))
	require.NoError(t, err)

	appID := app.AppID{Namespace: "namespace", ID: "app-id"}
	id, err := a.CreateAppSecret(ctx, secretentity.CreateAppSecretInput{AppID: appID, Key: "api_key", Value: "sk_test_value"})
	require.NoError(t, err)

	otherApp := app.AppID{Namespace: "namespace", ID: "other-app"}
	_, err = a.GetAppSecret(ctx, secretentity.NewSecretID(otherApp, id.ID, "api_key"))
	require.Error(t, err)

	_, err = a.GetAppSecret(ctx, secretentity.NewSecretID(appID, id.ID, "webhook_secret"))
	require.Error(t, err)
}

func TestNewEncryptedRequiresA32ByteKey(t *testing.T) {
	// given:
	// - encryption keys shorter than 32 bytes
	// when:
	// - an encrypting adapter is created with them
	// then:
	// - creation fails, so a weaker AES-128 or AES-192 key is never used
	for _, size := range []int{0, 16, 24, 31} {
		_, err := NewEncrypted(bytes.Repeat([]byte{1}, size))
		require.Error(t, err, "key size %d", size)
	}
}
