<?php

declare(strict_types=1);

namespace Lion\Security;

use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;
use OpenSSLAsymmetricKey;
use RuntimeException;
use stdClass;

/**
 * Allows you to generate the required configuration for public and private
 * keys, has methods that allow you to encrypt and decrypt data with RSA
 *
 * @property OpenSSLAsymmetricKey|false|null $publicKey [Represents the public
 * key object]
 * @property OpenSSLAsymmetricKey|false|null $privateKey [Represents the private
 * key object]
 * @property array<string, string>|stdClass $values [Property that stores the
 * values of any type of execution being performed 'encode, decode']
 * @property string $urlPath [Defines the path where the public and private keys
 * are stored]
 * @property string $rsaConfig [Defines the path where the openssl.cnf file is
 * stored to generate keys]
 * @property int $rsaPrivateKeyBits [Defines the number of Bits to generate the
 * keys]
 * @property string $rsaDefaultMd [Sets the default signing algorithm]
 *
 * @package Lion\Security
 */
class RSA implements ConfigInterface, EncryptionInterface, ObjectInterface
{
    /**
     * [Represents the public key object]
     *
     * @var OpenSSLAsymmetricKey|false|null $publicKey
     */
    private OpenSSLAsymmetricKey|false|null $publicKey = null;

    /**
     * [Represents the private key object]
     *
     * @var OpenSSLAsymmetricKey|false|null $privateKey
     */
    private OpenSSLAsymmetricKey|false|null $privateKey = null;

    /**
     * [Property that stores the values of any type of execution being
     * performed 'encode, decode']
     *
     * @var array<string, string>|stdClass $values
     */
    private array|stdClass $values = [];

    /**
     * [Defines the path where the public and private keys are stored]
     *
     * @var string $urlPath
     */
    private string $urlPath = './storage/keys/';

    /**
     * [Defines the path where the openssl.cnf file is stored to generate keys]
     *
     * @var string $rsaConfig
     */
    private string $rsaConfig = '/etc/ssl/openssl.cnf';

    /**
     * [Defines the number of Bits to generate the keys]
     *
     * @var int $rsaPrivateKeyBits
     */
    private int $rsaPrivateKeyBits = 2048;

    /**
     * [Sets the default signing algorithm]
     *
     * @var string $rsaDefaultMd
     */
    private string $rsaDefaultMd = 'sha256';

    /**
     * {@inheritDoc}
     */
    public function config(array $config): RSA
    {
        if (!empty($config['urlPath']) && '' !== $this->urlPath) {
            $this->urlPath = $config['urlPath'];
        }

        if (!empty($config['rsaConfig']) && '' !== $this->rsaConfig) {
            $this->rsaConfig = $config['rsaConfig'];
        }

        if (!empty($config['rsaPrivateKeyBits'])) {
            $this->rsaPrivateKeyBits = $config['rsaPrivateKeyBits'];
        }

        if (!empty($config['rsaDefaultMd']) && '' !== $this->rsaDefaultMd) {
            $this->rsaDefaultMd = $config['rsaDefaultMd'];
        }

        return $this;
    }

    /**
     * Returns the current array/object with the generated data
     *
     * @return array<string, string>|stdClass
     */
    public function get(): array|stdClass
    {
        $values = $this->values;

        $this->clean();

        return $values;
    }

    /**
     * {@inheritDoc}
     *
     * @throws InvalidConfigException [If the public key is null]
     * @throws RuntimeException [If the encrypted data is incorrect]
     */
    public function encode(string $key, string $value): RSA
    {
        $this->init();

        if (null === $this->publicKey) {
            throw new InvalidConfigException('Public key cannot be null', 500);
        }

        if ($this->publicKey instanceof OpenSSLAsymmetricKey) {
            openssl_public_encrypt($value, $data, $this->publicKey);

            if (is_array($this->values) && is_string($data)) {
                $this->values[$key] = $data;
            }

            if ($this->values instanceof stdClass && is_string($data)) {
                $this->values->{$key} = $data;
            }
        }

        return $this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws InvalidConfigException [If the private key is null]
     */
    public function decode(array $rows): RSA
    {
        $this->init();

        if (null === $this->privateKey) {
            throw new InvalidConfigException('The private key cannot be null', 500);
        }

        foreach ($rows as $key => $row) {
            if ($this->privateKey instanceof OpenSSLAsymmetricKey) {
                openssl_private_decrypt($row, $data, $this->privateKey);

                if (is_array($this->values) && is_string($data)) {
                    $this->values[$key] = $data;
                }

                if ($this->values instanceof stdClass && is_string($data)) {
                    $this->values->{$key} = $data;
                }
            }
        }

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function toObject(): RSA
    {
        if (is_array($this->values)) {
            $this->values = (object) $this->values;
        }

        return $this;
    }

    /**
     * Initialize keys stored in a path
     *
     * @return RSA
     */
    public function init(): RSA
    {
        if (null === $this->publicKey) {
            /** @var string $publicKey */
            $publicKey = file_get_contents($this->urlPath . 'public.key');

            $this->publicKey = openssl_pkey_get_public($publicKey);
        }

        if (null === $this->privateKey) {
            /** @var string $privateKey */
            $privateKey = file_get_contents($this->urlPath . 'private.key');

            $this->privateKey = openssl_pkey_get_private($privateKey);
        }

        return $this;
    }

    /**
     * Clear variables so they have their original value
     *
     * @return void
     */
    private function clean(): void
    {
        $this->values = [];

        $this->urlPath = './storage/keys/';

        $this->rsaConfig = '/etc/ssl/openssl.cnf';

        $this->rsaPrivateKeyBits = 2048;

        $this->rsaDefaultMd = 'sha256';
    }

    /**
     * Generate keys on a defined path
     *
     * @param string $urlPath [Defines the url where the key will be saved]
     * @param string $keyValue [Key content]
     * @param bool $isPublic [Determines if the key is public or private with a
     * boolean value]
     *
     * @return void
     */
    private function generateKeys(string $urlPath, string $keyValue, bool $isPublic = true): void
    {
        $path = '' === $urlPath ? $this->urlPath : $urlPath;

        file_put_contents((!$isPublic ? "{$path}private.key" : "{$path}public.key"), $keyValue);
    }

    /**
     * Create public and private key in a route
     *
     * @param string $urlPath [Defines the url where the key will be saved]
     *
     * @return RSA
     */
    public function create(string $urlPath = ''): RSA
    {
        $rsaConfig = [
            'config' => $this->rsaConfig,
            'private_key_bits' => $this->rsaPrivateKeyBits,
            'default_md' => $this->rsaDefaultMd
        ];

        $generate = openssl_pkey_new($rsaConfig);

        if ($generate instanceof OpenSSLAsymmetricKey) {
            openssl_pkey_export($generate, $privateKey, null, $rsaConfig);

            $publicKey = openssl_pkey_get_details($generate);

            if ($publicKey !== false && isset($publicKey['key']) && is_string($publicKey['key'])) {
                $this->generateKeys($urlPath, $publicKey['key']);
            }

            if (is_string($privateKey)) {
                $this->generateKeys($urlPath, $privateKey, false);
            }

            $this->init();
        }

        return $this;
    }

    /**
     * Returns the current path of the keys
     *
     * @return string
     */
    public function getUrlPath(): string
    {
        return $this->urlPath;
    }

    /**
     * Modify the current key path
     *
     * @param string $urlPath [Defines the url where the key will be saved]
     *
     * @return RSA
     */
    public function setUrlPath(string $urlPath): RSA
    {
        $this->urlPath = $urlPath;

        return $this;
    }

    /**
     * Returns the current public key
     *
     * @return OpenSSLAsymmetricKey|false|null
     */
    public function getPublicKey(): OpenSSLAsymmetricKey|false|null
    {
        return $this->publicKey;
    }

    /**
     * Returns the current private key
     *
     * @return OpenSSLAsymmetricKey|false|null
     */
    public function getPrivateKey(): OpenSSLAsymmetricKey|false|null
    {
        return $this->privateKey;
    }
}
