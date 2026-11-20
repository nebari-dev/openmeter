package adapter

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/openmeterio/openmeter/openmeter/app"
	"github.com/openmeterio/openmeter/openmeter/secret"
	secretentity "github.com/openmeterio/openmeter/openmeter/secret/entity"
)

// KeySize is the size in bytes of the key NewEncrypted takes (AES-256).
const KeySize = 32

// encryptedPrefix marks a secret id that holds the AES-GCM encrypted value.
const encryptedPrefix = "enc:v1:"

// NewEncrypted returns an adapter that stores each secret as its AES-256-GCM
// encrypted value, so the database holds ciphertext instead of the secret.
func NewEncrypted(key []byte) (secret.Adapter, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret encryption key must be %d bytes, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &encryptedAdapter{aead: aead}, nil
}

var _ secret.Adapter = (*encryptedAdapter)(nil)

type encryptedAdapter struct {
	aead cipher.AEAD
}

func (a *encryptedAdapter) CreateAppSecret(ctx context.Context, input secretentity.CreateAppSecretInput) (secretentity.SecretID, error) {
	id, err := a.encrypt(input.Value, input.AppID, input.Key)
	if err != nil {
		return secretentity.SecretID{}, err
	}

	return secretentity.NewSecretID(input.AppID, id, input.Key), nil
}

func (a *encryptedAdapter) UpdateAppSecret(ctx context.Context, input secretentity.UpdateAppSecretInput) (secretentity.SecretID, error) {
	id, err := a.encrypt(input.Value, input.AppID, input.Key)
	if err != nil {
		return input.SecretID, err
	}

	return secretentity.NewSecretID(input.AppID, id, input.Key), nil
}

func (a *encryptedAdapter) GetAppSecret(ctx context.Context, input secretentity.GetAppSecretInput) (secretentity.Secret, error) {
	value, err := a.decrypt(input.ID, input.AppID, input.Key)
	if err != nil {
		return secretentity.Secret{}, err
	}

	return secretentity.Secret{SecretID: input, Value: value}, nil
}

func (a *encryptedAdapter) DeleteAppSecret(ctx context.Context, input secretentity.DeleteAppSecretInput) error {
	return nil
}

func (a *encryptedAdapter) encrypt(value string, appID app.AppID, key string) (string, error) {
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := a.aead.Seal(nonce, nonce, []byte(value), associatedData(appID, key))

	return encryptedPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (a *encryptedAdapter) decrypt(id string, appID app.AppID, key string) (string, error) {
	// Secrets written by the plaintext adapter store the value as the id.
	if !strings.HasPrefix(id, encryptedPrefix) {
		return id, nil
	}

	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, encryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	nonceSize := a.aead.NonceSize()
	if len(sealed) < nonceSize {
		return "", fmt.Errorf("decode secret: too short")
	}

	value, err := a.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], associatedData(appID, key))
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}

	return string(value), nil
}

// associatedData binds a ciphertext to the app and key it was written for, so
// a stored id copied to another app or secret fails to decrypt.
func associatedData(appID app.AppID, key string) []byte {
	return []byte(appID.Namespace + "\x00" + appID.ID + "\x00" + key)
}
