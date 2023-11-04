<?php

namespace LionSecurity;

use LionSecurity\Exceptions\InvalidConfigException;
use LionSecurity\Exceptions\InvalidKeyException;

class AES
{
    const AES_128_CBC = "aes-128-cbc";
    const AES_128_CBC_CTS = "aes-128-cbc-cts";
    const AES_128_CBC_HMAC_SHA1 = "aes-128-cbc-hmac-sha1";
    const AES_128_CBC_HMAC_SHA256 = "aes-128-cbc-hmac-sha256";
    const AES_128_CCM = "aes-128-ccm";
    const AES_128_CFB = "aes-128-cfb";
    const AES_128_CFB1 = "aes-128-cfb1";
    const AES_128_CFB8 = "aes-128-cfb8";
    const AES_128_CTR = "aes-128-ctr";
    const AES_128_ECB = "aes-128-ecb";
    const AES_128_GCM = "aes-128-gcm";
    const AES_128_OCB = "aes-128-ocb";
    const AES_128_OFB = "aes-128-ofb";
    const AES_128_SIV = "aes-128-siv";
    const AES_128_WRAP = "aes-128-wrap";
    const AES_128_WRAP_INV = "aes-128-wrap-inv";
    const AES_128_WRAP_PAD = "aes-128-wrap-pad";
    const AES_128_WRAP_PAD_INV = "aes-128-wrap-pad-inv";
    const AES_128_XTS = "aes-128-xts";
    const AES_192_CBC = "aes-192-cbc";
    const AES_192_CBC_CTS = "aes-192-cbc-cts";
    const AES_192_CCM = "aes-192-ccm";
    const AES_192_CFB = "aes-192-cfb";
    const AES_192_CFB1 = "aes-192-cfb1";
    const AES_192_CFB8 = "aes-192-cfb8";
    const AES_192_CTR = "aes-192-ctr";
    const AES_192_ECB = "aes-192-ecb";
    const AES_192_GCM = "aes-192-gcm";
    const AES_192_OCB = "aes-192-ocb";
    const AES_192_OFB = "aes-192-ofb";
    const AES_192_SIV = "aes-192-siv";
    const AES_192_WRAP = "aes-192-wrap";
    const AES_192_WRAP_INV = "aes-192-wrap-inv";
    const AES_192_WRAP_PAD = "aes-192-wrap-pad";
    const AES_192_WRAP_PAD_INV = "aes-192-wrap-pad-inv";
    const AES_256_CBC = "aes-256-cbc";
    const AES_256_CBC_CTS = "aes-256-cbc-cts";
    const AES_256_CBC_HMAC_SHA1 = "aes-256-cbc-hmac-sha1";
    const AES_256_CBC_HMAC_SHA256 = "aes-256-cbc-hmac-sha256";
    const AES_256_CCM = "aes-256-ccm";
    const AES_256_CFB = "aes-256-cfb";
    const AES_256_CFB1 = "aes-256-cfb1";
    const AES_256_CFB8 = "aes-256-cfb8";
    const AES_256_CTR = "aes-256-ctr";
    const AES_256_ECB = "aes-256-ecb";
    const AES_256_GCM = "aes-256-gcm";
    const AES_256_OCB = "aes-256-ocb";
    const AES_256_OFB = "aes-256-ofb";
    const AES_256_SIV = "aes-256-siv";
    const AES_256_WRAP = "aes-256-wrap";
    const AES_256_WRAP_INV = "aes-256-wrap-inv";
    const AES_256_WRAP_PAD = "aes-256-wrap-pad";
    const AES_256_WRAP_PAD_INV = "aes-256-wrap-pad-inv";
    const AES_256_XTS = "aes-256-xts";

    private array|object $values = [];
    private string $method = '';
    private string $key = '';
    private string $iv = '';

    /**
     * Clear variables so they have their original value
     * */
    private function clean(): void
    {
        $this->values = [];
        $this->method = '';
        $this->key = '';
        $this->iv = '';
    }

    /**
     * Get length of certain encryption method
     * */
    public function cipherKeyLength(string $aesMethod): int|false
    {
        $length = match(trim(strtolower($aesMethod))) {
            'aes-128-cbc' => 16,
            'aes-128-cbc-hmac-sha1' => 16,
            'aes-128-cbc-hmac-sha256' => 16,
            'aes-128-ccm' => 16,
            'aes-128-cfb' => 16,
            'aes-128-cfb1' => 16,
            'aes-128-cfb8' => 16,
            'aes-128-ctr' => 16,
            'aes-128-ecb' => 16,
            'aes-128-gcm' => 16,
            'aes-128-ocb' => 16,
            'aes-128-ofb' => 16,
            'aes-128-wrap' => 16,
            'aes-128-wrap-pad' => 16,
            'aes-128-xts' => 32,
            'aes-192-cbc' => 24,
            'aes-192-ccm' => 24,
            'aes-192-cfb' => 24,
            'aes-192-cfb1' => 24,
            'aes-192-cfb8' => 24,
            'aes-192-ctr' => 24,
            'aes-192-ecb' => 24,
            'aes-192-gcm' => 24,
            'aes-192-ocb' => 24,
            'aes-192-ofb' => 24,
            'aes-192-wrap' => 24,
            'aes-192-wrap-pad' => 24,
            'aes-256-cbc' => 32,
            'aes-256-cbc-hmac-sha1' => 32,
            'aes-256-cbc-hmac-sha256' => 32,
            'aes-256-ccm' => 32,
            'aes-256-cfb' => 32,
            'aes-256-cfb1' => 32,
            'aes-256-cfb8' => 32,
            'aes-256-ctr' => 32,
            'aes-256-ecb' => 32,
            'aes-256-gcm' => 32,
            'aes-256-ocb' => 32,
            'aes-256-ofb' => 32,
            'aes-256-wrap' => 32,
            'aes-256-wrap-pad' => 32,
            'aes-256-xts' => 64,
            default => false
        };

        return $length;
    }

    /**
     * Define settings for AES encryption
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
     * Defines the encryption method
     * */
    public function method(string $method): AES
    {
        $this->method = $method;

        return $this;
    }

    /**
     * Defines the encryption key
     * */
    public function key(string $key): AES
    {
        $lenght = $this->cipherKeyLength($this->method);

        if (strlen($key) !== $lenght) {
            throw new InvalidKeyException(
                "Key passed is not {$lenght} bytes long"
            );
        }

        $this->key = $key;

        return $this;
    }

    /**
     * Defines the encryption iv
     * */
    public function iv(string $iv): AES
    {
        $lenght = $this->cipherKeyLength($this->method);

        if (strlen($iv) !== $lenght) {
            throw new InvalidKeyException(
                "Iv passed is not {$lenght} bytes long"
            );
        }

        $this->iv = $iv;

        return $this;
    }

    /**
     * Encrypt data with defined settings
     * */
    public function encode(string $key, string $value): AES
    {
        $encrypt = openssl_encrypt($value, $this->method, md5($this->key), OPENSSL_RAW_DATA, $this->iv);
        $this->values[$key] = base64_encode($encrypt);

        return $this;
    }

    /**
     * Decodes the data with the defined settings
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
     * Converts the list with data to an object
     * */
    public function toObject(): AES
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
