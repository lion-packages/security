<?php

declare(strict_types=1);

namespace Lion\Security;

use Exception;
use JsonException;
use Lion\Security\Exceptions\AESException;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;
use OpenSSLAsymmetricKey;
use Random\RandomException;
use stdClass;

/**
 * It allows you to generate the configuration required for AES encryption and
 * decryption, it has methods that allow you to encrypt and decrypt data with
 * AES.
 */
class AES implements ConfigInterface, EncryptionInterface, ObjectInterface
{
    /**
     * AES-256-GCM is a highly secure symmetric encryption algorithm that combines
     * the Advanced Encryption Standard (AES) with a 256-bit key and Galois/Counter
     * (GCM) mode of operation, offering confidentiality (encryption) and
     * authenticity (integrity) of data in a single step, making it fast and robust
     * for protecting sensitive information in applications such as web security
     * (HTTPS), VPNs, and secure messaging, ensuring that data is not only
     * unreadable but also tamper-proof.
     *
     * @const AES_256_GCM
     */
    public const string AES_256_GCM = 'aes-256-gcm';

    /**
     * It represents the key property in the configuration.
     *
     * @const KEY
     */
    public const string KEY = 'key';

    /**
     * It represents the encrypted block.
     *
     * @const DATA
     */
    public const string DATA = 'data';

    /**
     * It represents the iv in the cipher block.
     *
     * @const IV
     */
    public const string IV = 'iv';

    /**
     * It represents the tag in the cipher block.
     *
     * @const TAG
     */
    public const string TAG = 'tag';

    /**
     * Property that stores the values of any type of execution being performed
     *  'create, encode, decode'.
     *
     * @var array<string, string>|stdClass $values
     */
    private array|stdClass $values = [];

    /**
     * Property that contains the configuration defined for AES processes.
     *
     * @var array{
     *     key: int|null|string|OpenSSLAsymmetricKey
     * } $config
     */
    private array $config;

    /**
     * {@inheritDoc}
     */
    public function config(array $config): AES
    {
        $this->config = $config;

        return $this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws JsonException If encoding to JSON fails.
     * @throws RandomException
     */
    public function encode(array $data): AES
    {
        $iv = random_bytes(12);

        $tag = '';

        $plaintext = json_encode($data, JSON_THROW_ON_ERROR);

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::AES_256_GCM,
            /** @phpstan-ignore-next-line */
            hex2bin($this->config[self::KEY]),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            /** @phpstan-ignore-next-line */
            throw new AESException(openssl_error_string(), 500);
        }

        $this->values = [
            self::DATA => base64_encode($ciphertext),
            self::IV => base64_encode($iv),
            self::TAG => base64_encode($tag),
        ];

        return $this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws JsonException If encoding to JSON fails.
     */
    public function decode(array $encrypted): AES
    {
        $plaintext = openssl_decrypt(
            base64_decode($encrypted['data']),
            self::AES_256_GCM,
            /** @phpstan-ignore-next-line */
            hex2bin($this->config['key']),
            OPENSSL_RAW_DATA,
            base64_decode($encrypted['iv']),
            base64_decode($encrypted['tag'])
        );

        if ($plaintext === false) {
            throw new AESException('Authentication failed', 500);
        }

        /** @phpstan-ignore-next-line */
        $this->values = json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function toObject(): AES
    {
        if (is_array($this->values)) {
            $this->values = (object) $this->values;
        }

        return $this;
    }

    /**
     * Clear variables so they have their original value.
     *
     * @return void
     */
    private function clean(): void
    {
        $this->values = [];

        /** @phpstan-ignore-next-line */
        $this->config = [];
    }

    /**
     * Creates key and iv for aes encryption.
     *
     * @return AES
     *
     * @throws Exception If the algorithm is not supported.
     */
    public function create(): AES
    {
        $this->values = [
            'key' => bin2hex(random_bytes(32)), // 256 bits
            'iv' => bin2hex(random_bytes(12)), // GCM estándar
        ];

        return $this;
    }

    /**
     * Returns the current array/object with the generated data.
     *
     * @return array<string, string>|stdClass
     *
     * @infection-ignore-all
     */
    public function get(): array|stdClass
    {
        $values = $this->values;

        $this->clean();

        return $values;
    }
}
