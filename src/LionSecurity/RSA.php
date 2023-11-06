<?php

declare(strict_types=1);

namespace LionSecurity;

use OpenSSLAsymmetricKey;

class RSA
{
	private ?OpenSSLAsymmetricKey $publicKey = null;
	private ?OpenSSLAsymmetricKey $privateKey = null;

    private array|object $values = [];
	private string $urlPath = './storage/keys/';
    private string $rsaConfig = '/etc/ssl/openssl.cnf';
    private int $rsaPrivateKeyBits = 2048;
    private string $rsaDefaultMd = 'sha256';

    /**
     * Clear variables so they have their original value
     * */
    private function clean(): void
    {
        $this->values = [];
        $this->urlPath = './storage/keys/';
        $this->rsaConfig = '/etc/ssl/openssl.cnf';
        $this->rsaPrivateKeyBits = 2048;
        $this->rsaDefaultMd = 'sha256';
    }

    /**
     * Define settings for AES encryption
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
     * Generate keys on a defined path
     * */
    private function generateKeys(string $urlPath, string $keyValue, bool $isPublic = true): void
    {
        $path = '' === $urlPath ? $this->urlPath : $urlPath;
        file_put_contents((!$isPublic ? "{$path}private.key" : "{$path}public.key"), $keyValue);
    }

    /**
     * Create public and private key in a route
     * */
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
     * Encrypt data with defined settings
     * */
	public function encode(string $key, string $value): RSA
    {
		$this->init();
        openssl_public_encrypt($value, $data, $this->publicKey);
        $this->values[$key] = $data;

        return $this;
	}

    /**
     * Decodes the data with the defined settings
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
     * Returns the current path of the keys
     * */
	public function getUrlPath(): string
    {
		return $this->urlPath;
	}

    /**
     * Modify the current key path
     * */
	public function setUrlPath(string $urlPath): RSA
    {
		$this->urlPath = $urlPath;

        return $this;
	}

    /**
     * Returns the current public key
     * */
	public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
		return $this->publicKey;
	}

    /**
     * Returns the current private key
     * */
	public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
		return $this->privateKey;
	}

    /**
     * Modify the path for the configuration file used by OpenSSL
     * */
    public function rsaConfig(string $rsaConfig): RSA
    {
        $this->rsaConfig = $rsaConfig;

        return $this;
    }

    /**
     * Modify by specifying the length of the RSA key
     * */
    public function rsaPrivateKeyBits(int $rsaPrivateKeyBits): RSA
    {
        $this->rsaPrivateKeyBits = $rsaPrivateKeyBits;

        return $this;
    }

    /**
     * Modify the cryptographic protocol configuration: sha256
     * */
    public function rsaDefaultMd(string $rsaDefaultMd): RSA
    {
        $this->rsaDefaultMd = $rsaDefaultMd;

        return $this;
    }

    /**
     * Initialize keys stored in a path
     * */
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
     * Converts the list with data to an object
     * */
    public function toObject(): RSA
    {
        if (gettype($this->values) === 'array') {
            $this->values = (object) $this->values;
        }

        return $this;
    }

    /**
     * Returns the current array/object with the encrypted/decrypted data
     * */
    public function get(): array|object
    {
        $values = $this->values;
        $this->clean();

        return $values;
    }
}
