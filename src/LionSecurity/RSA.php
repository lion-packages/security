<?php

declare(strict_types=1);

namespace Lion\Security;

use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;
use OpenSSLAsymmetricKey;

/**
 * Allows you to generate the required configuration for public and private
 * keys, has methods that allow you to encrypt and decrypt data with RSA
 *
 * @package Lion\Security
 */
class RSA implements ConfigInterface, EncryptionInterface, ObjectInterface
{
    /**
     * [Represents the public key object]
     *
     * @var null|OpenSSLAsymmetricKey $publicKey
     */
	private ?OpenSSLAsymmetricKey $publicKey = null;

    /**
     * [Represents the private key object]
     *
     * @var null|OpenSSLAsymmetricKey $privateKey
     */
	private ?OpenSSLAsymmetricKey $privateKey = null;

    /**
     * [Property that stores the values of any type of execution being
     * performed 'encode, decode']
     *
     * @var array|object $values
     */
    private array|object $values = [];

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
     * @var string
     */
    private string $rsaDefaultMd = 'sha256';

    /**
     * {@inheritdoc}
     * */
    public function config(array $config): RSA
    {
        if (!empty($config['urlPath']) && '' !== $this->urlPath) {
            $this->urlPath = $config['urlPath'];
        }

        if (!empty($config['rsaConfig']) && '' !== $this->rsaConfig) {
            $this->rsaConfig = $config['rsaConfig'];
        }

        if (!empty($config['rsaPrivateKeyBits']) && '' !== $this->rsaPrivateKeyBits) {
            $this->rsaPrivateKeyBits = $config['rsaPrivateKeyBits'];
        }

        if (!empty($config['rsaDefaultMd']) && '' !== $this->rsaDefaultMd) {
            $this->rsaDefaultMd = $config['rsaDefaultMd'];
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     * */
    public function get(): array|object
    {
        $values = $this->values;

        $this->clean();

        return $values;
    }

    /**
     * {@inheritdoc}
     * */
    public function encode(string $key, string $value): RSA
    {
        $this->init();

        openssl_public_encrypt($value, $data, $this->publicKey);

        $this->values[$key] = $data;

        return $this;
    }

    /**
     * {@inheritdoc}
     * */
    public function decode(array $rows): RSA
    {
        $this->init();

        foreach ($rows as $key => $row) {
            openssl_private_decrypt($row, $data, $this->privateKey);

            $this->values[$key] = $data;
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     * */
    public function toObject(): RSA
    {
        if (gettype($this->values) === 'array') {
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
            $this->publicKey = openssl_pkey_get_public(file_get_contents($this->urlPath . 'public.key'));
        }

        if (null === $this->privateKey) {
            $this->privateKey = openssl_pkey_get_private(file_get_contents($this->urlPath . 'private.key'));
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
     * @param  string $urlPath [Defines the url where the key will be saved]
     * @param  string $keyValue [Key content]
     * @param  bool $isPublic [Determines if the key is public or private with
     * a boolean value]
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
     * @param  string $urlPath [Defines the url where the key will be saved]
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

		openssl_pkey_export($generate, $private, null, $rsaConfig);

		$public = openssl_pkey_get_details($generate);

        $this->generateKeys($urlPath, $public['key']);

        $this->generateKeys($urlPath, $private, false);

        $this->init();

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
     * @return RSA;
     */
	public function setUrlPath(string $urlPath): RSA
    {
		$this->urlPath = $urlPath;

        return $this;
	}

    /**
     * Returns the current public key
     *
     * @return null|OpenSSLAsymmetricKey
     */
	public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
		return $this->publicKey;
	}

    /**
     * Returns the current private key
     *
     * @return null|OpenSSLAsymmetricKey
     * */
	public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
		return $this->privateKey;
	}

    /**
     * Modify the path for the configuration file used by OpenSSL
     *
     * @param  string $rsaConfig [Defines the path of the openssl.cnf file]
     *
     * @return RSA
     */
    public function rsaConfig(string $rsaConfig): RSA
    {
        $this->rsaConfig = $rsaConfig;

        return $this;
    }

    /**
     * Modify by specifying the length of the RSA key
     *
     * @param  int $rsaPrivateKeyBits [Defines the number of bits]
     *
     * @return RSA
     */
    public function rsaPrivateKeyBits(int $rsaPrivateKeyBits): RSA
    {
        $this->rsaPrivateKeyBits = $rsaPrivateKeyBits;

        return $this;
    }

    /**
     * Modify the cryptographic protocol configuration: 'sha256'
     *
     * @param  string $rsaDefaultMd [Encryption protocol]
     *
     * @return RSA
     */
    public function rsaDefaultMd(string $rsaDefaultMd): RSA
    {
        $this->rsaDefaultMd = $rsaDefaultMd;

        return $this;
    }
}
