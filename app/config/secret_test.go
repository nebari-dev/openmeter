package config

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretConfigurationReadsTheKeyFromTheEnvironment(t *testing.T) {
	// given:
	// - SECRET_ENCRYPTIONKEY holds 32 bytes as hex
	// when:
	// - the configuration is loaded
	// then:
	// - the secret configuration returns those 32 bytes as the key
	want := []byte(strings.Repeat("k", 32))
	t.Setenv("SECRET_ENCRYPTIONKEY", hex.EncodeToString(want))

	v, flags := viper.New(), pflag.NewFlagSet("OpenMeter", pflag.ContinueOnError)
	SetViperDefaults(v, flags)

	var conf Configuration
	require.NoError(t, v.Unmarshal(&conf, viper.DecodeHook(DecodeHook())))

	key, err := conf.Secret.Key()
	require.NoError(t, err)
	assert.Equal(t, want, key)
}

func TestSecretConfigurationValidate(t *testing.T) {
	// given:
	// - no key, a valid key, and keys that are not hex of 32 bytes
	// when:
	// - the secret configuration is validated
	// then:
	// - no key passes (processes without app secrets don't need one), a valid key
	//   passes, and a malformed key fails
	require.NoError(t, SecretConfiguration{}.Validate())
	require.NoError(t, SecretConfiguration{EncryptionKey: strings.Repeat("ab", 32)}.Validate())

	for _, key := range []string{"not-hex", strings.Repeat("ab", 16)} {
		assert.Error(t, SecretConfiguration{EncryptionKey: key}.Validate(), "key %q", key)
	}
}

func TestConfigurationValidateRejectsAMalformedSecretKey(t *testing.T) {
	// given:
	// - an otherwise valid configuration
	// when:
	// - its secret encryption key is not hex of 32 bytes
	// then:
	// - the configuration fails validation, so OpenMeter stops at startup
	v, flags := viper.New(), pflag.NewFlagSet("OpenMeter", pflag.ContinueOnError)
	SetViperDefaults(v, flags)
	v.SetConfigFile("testdata/complete.yaml")
	require.NoError(t, v.ReadInConfig())

	var conf Configuration
	require.NoError(t, v.Unmarshal(&conf, viper.DecodeHook(DecodeHook())))
	require.NoError(t, conf.Validate())

	conf.Secret.EncryptionKey = "not-hex"
	assert.Error(t, conf.Validate())
}
