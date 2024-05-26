<?php

declare(strict_types=1);

namespace Lion\Security;

use Lion\Security\Exceptions\AESException;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;

/**
 * It allows you to generate the configuration required for AES encryption and
 * decryption, it has methods that allow you to encrypt and decrypt data with
 * AES
 *
 * @property array|object $values [Property that stores the values of any type
 * of execution being performed 'create, encode, decode']
 * @property array $config [Property that contains the configuration defined for
 * AES processes]
 *
 * @package Lion\Security
 */
class AES implements ConfigInterface, EncryptionInterface, ObjectInterface
{
    /**
     * [It's a robust encryption method with a 256-bit key size and uses Cipher
     * Block Chaining (CBC) mode]
     *
     * @const AES_256_CBC
     */
    const AES_256_CBC = 'aes-256-cbc';

    /**
     * [Property that stores the values of any type of execution being
     * performed 'create, encode, decode']
     *
     * @var array|object $values
     */
    private array|object $values = [];

    /**
     * [Property that contains the configuration defined for AES processes]
     *
     * @var array $config
     */
    private array $config = [];

    /**
     * {@inheritdoc}
     * */
    public function config(array|object $config): AES
    {
        $this->config = (array) $config;

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
        $encrypt = openssl_encrypt(
            $value,
            $this->config['method'],
            hex2bin($this->config['key']),
            OPENSSL_RAW_DATA,
            hex2bin($this->config['iv'])
        );

        if (!$encrypt) {
            throw new AESException(openssl_error_string());
        }

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
                $this->config['method'],
                hex2bin($this->config['key']),
                OPENSSL_RAW_DATA,
                hex2bin($this->config['iv'])
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

        $this->config = [];
    }

    /**
     * Get length of certain encryption method
     *
     * @param string $method [AES algorithm type]
     *
     * @return bool|int
     */
    public function cipherKeyLength(string $method): bool|int
    {
        $length = match (trim(strtolower($method))) {
            self::AES_256_CBC => 32,
            default => false
        };

        return $length;
    }

    /**
     * Creates key and iv for aes encryption
     *
     * @param string $method [AES algorithm type]
     *
     * @return AES
     */
    public function create(string $method): AES
    {
        $this->values = [
            'key' => bin2hex(openssl_random_pseudo_bytes($this->cipherKeyLength($method))),
            'iv' => bin2hex(openssl_random_pseudo_bytes(16)),
            'method' => $method
        ];

        return $this;
    }
}
