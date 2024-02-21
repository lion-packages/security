<?php

declare(strict_types=1);

namespace Lion\Security;

use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;

class AES implements ConfigInterface, EncryptionInterface, ObjectInterface
{
    const AES_128_CBC = 'aes-128-cbc';
    const AES_128_CBC_CTS = 'aes-128-cbc-cts';
    const AES_128_CBC_HMAC_SHA1 = 'aes-128-cbc-hmac-sha1';
    const AES_128_CBC_HMAC_SHA256 = 'aes-128-cbc-hmac-sha256';
    const AES_128_CCM = 'aes-128-ccm';
    const AES_128_CFB = 'aes-128-cfb';
    const AES_128_CFB1 = 'aes-128-cfb1';
    const AES_128_CFB8 = 'aes-128-cfb8';
    const AES_128_CTR = 'aes-128-ctr';
    const AES_128_ECB = 'aes-128-ecb';
    const AES_128_GCM = 'aes-128-gcm';
    const AES_128_OCB = 'aes-128-ocb';
    const AES_128_OFB = 'aes-128-ofb';
    const AES_128_SIV = 'aes-128-siv';
    const AES_128_WRAP = 'aes-128-wrap';
    const AES_128_WRAP_INV = 'aes-128-wrap-inv';
    const AES_128_WRAP_PAD = 'aes-128-wrap-pad';
    const AES_128_WRAP_PAD_INV = 'aes-128-wrap-pad-inv';
    const AES_128_XTS = 'aes-128-xts';
    const AES_192_CBC = 'aes-192-cbc';
    const AES_192_CBC_CTS = 'aes-192-cbc-cts';
    const AES_192_CCM = 'aes-192-ccm';
    const AES_192_CFB = 'aes-192-cfb';
    const AES_192_CFB1 = 'aes-192-cfb1';
    const AES_192_CFB8 = 'aes-192-cfb8';
    const AES_192_CTR = 'aes-192-ctr';
    const AES_192_ECB = 'aes-192-ecb';
    const AES_192_GCM = 'aes-192-gcm';
    const AES_192_OCB = 'aes-192-ocb';
    const AES_192_OFB = 'aes-192-ofb';
    const AES_192_SIV = 'aes-192-siv';
    const AES_192_WRAP = 'aes-192-wrap';
    const AES_192_WRAP_INV = 'aes-192-wrap-inv';
    const AES_192_WRAP_PAD = 'aes-192-wrap-pad';
    const AES_192_WRAP_PAD_INV = 'aes-192-wrap-pad-inv';
    const AES_256_CBC = 'aes-256-cbc';
    const AES_256_CBC_CTS = 'aes-256-cbc-cts';
    const AES_256_CBC_HMAC_SHA1 = 'aes-256-cbc-hmac-sha1';
    const AES_256_CBC_HMAC_SHA256 = 'aes-256-cbc-hmac-sha256';
    const AES_256_CCM = 'aes-256-ccm';
    const AES_256_CFB = 'aes-256-cfb';
    const AES_256_CFB1 = 'aes-256-cfb1';
    const AES_256_CFB8 = 'aes-256-cfb8';
    const AES_256_CTR = 'aes-256-ctr';
    const AES_256_ECB = 'aes-256-ecb';
    const AES_256_GCM = 'aes-256-gcm';
    const AES_256_OCB = 'aes-256-ocb';
    const AES_256_OFB = 'aes-256-ofb';
    const AES_256_SIV = 'aes-256-siv';
    const AES_256_WRAP = 'aes-256-wrap';
    const AES_256_WRAP_INV = 'aes-256-wrap-inv';
    const AES_256_WRAP_PAD = 'aes-256-wrap-pad';
    const AES_256_WRAP_PAD_INV = 'aes-256-wrap-pad-inv';
    const AES_256_XTS = 'aes-256-xts';

    private array|object $values = [];
    private string $method = '';
    private string $key = '';
    private string $iv = '';

    /**
     * {@inheritdoc}
     * */
    public function config(array $config): AES
    {
        if (empty($config['key'])) {
            throw new InvalidConfigException('The key has not been defined');
        } else {
            $this->key = $config['key'];
        }

        if (empty($config['iv'])) {
            throw new InvalidConfigException('The Iv has not been defined');
        } else {
            $this->iv = $config['iv'];
        }

        if (empty($config['method']) && '' === $this->method) {
            $this->method = self::AES_256_CBC;
        } else {
            $this->method = $config['method'];
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
    public function encode(string $key, string $value): AES
    {
        $encrypt = openssl_encrypt($value, $this->method, md5($this->key), OPENSSL_RAW_DATA, $this->iv);
        $this->values[$key] = base64_encode($encrypt);

        return $this;
    }

    /**
     * {@inheritdoc}
     * */
    public function decode(array $rows): AES
    {
        foreach ($rows as $key => $row) {
            $this->values[$key] = openssl_decrypt(
                base64_decode($row),
                $this->method,
                md5($this->key),
                OPENSSL_RAW_DATA,
                $this->iv
            );
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     * */
    public function toObject(): AES
    {
        if (gettype($this->values) === 'array') {
            $this->values = (object) $this->values;
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
        $this->method = '';
        $this->key = '';
        $this->iv = '';
    }

    /**
     * Get length of certain encryption method
     *
     * @param  string $method [AES algorithm type]
     *
     * @return int|false
     */
    public function cipherKeyLength(string $method): int|false
    {
        $length = match (trim(strtolower($method))) {
            self::AES_128_CBC => 16,
            self::AES_128_CBC_CTS => 16,
            self::AES_128_CBC_HMAC_SHA1 => 16,
            self::AES_128_CBC_HMAC_SHA256 => 16,
            self::AES_128_CCM => 16,
            self::AES_128_CFB => 16,
            self::AES_128_CFB1 => 16,
            self::AES_128_CFB8 => 16,
            self::AES_128_CTR => 16,
            self::AES_128_ECB => 16,
            self::AES_128_GCM => 16,
            self::AES_128_OCB => 16,
            self::AES_128_OFB => 16,
            self::AES_128_SIV => 16,
            self::AES_128_WRAP => 16,
            self::AES_128_WRAP_INV => 16,
            self::AES_128_WRAP_PAD => 16,
            self::AES_128_WRAP_PAD_INV => 16,
            self::AES_128_XTS => 16,
            self::AES_192_CBC => 24,
            self::AES_192_CBC_CTS => 24,
            self::AES_192_CCM => 24,
            self::AES_192_CFB => 24,
            self::AES_192_CFB1 => 24,
            self::AES_192_CFB8 => 24,
            self::AES_192_CTR => 24,
            self::AES_192_ECB => 24,
            self::AES_192_GCM => 24,
            self::AES_192_OCB => 24,
            self::AES_192_OFB => 24,
            self::AES_192_SIV => 24,
            self::AES_192_WRAP => 24,
            self::AES_192_WRAP_INV => 24,
            self::AES_192_WRAP_PAD => 24,
            self::AES_192_WRAP_PAD_INV => 24,
            self::AES_256_CBC => 32,
            self::AES_256_CBC_CTS => 32,
            self::AES_256_CBC_HMAC_SHA1 => 32,
            self::AES_256_CBC_HMAC_SHA256 => 32,
            self::AES_256_CCM => 32,
            self::AES_256_CFB => 32,
            self::AES_256_CFB1 => 32,
            self::AES_256_CFB8 => 32,
            self::AES_256_CTR => 32,
            self::AES_256_ECB => 32,
            self::AES_256_GCM => 32,
            self::AES_256_OCB => 32,
            self::AES_256_OFB => 32,
            self::AES_256_SIV => 32,
            self::AES_256_WRAP => 32,
            self::AES_256_WRAP_INV => 32,
            self::AES_256_WRAP_PAD => 32,
            self::AES_256_WRAP_PAD_INV => 32,
            self::AES_256_XTS => 32,
            default => false
        };

        return $length;
    }

    /**
     * Creates key and iv for aes encryption
     *
     * @param  string $method [AES algorithm type]
     *
     * @return AES
     */
    public function create(string $method): AES
    {
        $bits = $this->cipherKeyLength($method);

        $this->values = [
            'bits' => $bits,
            'key' => bin2hex(random_bytes($bits / 2)),
            'iv' => bin2hex(random_bytes($bits / 2))
        ];

        return $this;
    }

    /**
     * Defines the encryption method
     *
     * @param  string $method [AES algorithm type]
     *
     * @return AES
     */
    public function method(string $method): AES
    {
        $this->method = $method;

        return $this;
    }

    /**
     * Defines the encryption key
     *
     * @param  string $key [AES encryption KEY]
     *
     * @return AES
     */
    public function key(string $key): AES
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Defines the encryption iv
     *
     * @param  string $iv [AES encryption IV]
     *
     * @return AES
     */
    public function iv(string $iv): AES
    {
        $this->iv = $iv;

        return $this;
    }
}
