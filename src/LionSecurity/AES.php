<?php

declare(strict_types=1);

namespace Lion\Security;

use Exception;
use Lion\Security\Exceptions\AESException;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;
use OpenSSLAsymmetricKey;
use stdClass;

/**
 * It allows you to generate the configuration required for AES encryption and
 * decryption, it has methods that allow you to encrypt and decrypt data with
 * AES
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
    public const string AES_256_CBC = 'aes-256-cbc';

    /**
     * [Property that stores the values of any type of execution being
     * performed 'create, encode, decode']
     *
     * @var array<string, string>|stdClass $values
     */
    private array|stdClass $values = [];

    /**
     * [Property that contains the configuration defined for AES processes]
     *
     * @var array<string, int|string|OpenSSLAsymmetricKey> $config
     */
    private array $config = [

        
    ];

    /**
     * {@inheritDoc}
     */
    public function config(array $config): AES
    {
        $this->config = $config;

        return $this;
    }

    /**
     * Returns the current array/object with the generated data
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

    /**
     * {@inheritDoc}
     *
     * @throws AESException
     */
    public function encode(string $key, string $value): AES
    {
        /** @var string $method */
        $method = $this->config['method'];

        /** @var string $passphrase */
        $passphrase = $this->config['passphrase'];

        /** @var string $hex2BinPassphrase */
        $hex2BinPassphrase = hex2bin($passphrase);

        /** @var string $iv */
        $iv = $this->config['iv'];

        /** @var string $hex2BinIv */
        $hex2BinIv = hex2bin($iv);

        $encrypt = openssl_encrypt($value, $method, $hex2BinPassphrase, OPENSSL_RAW_DATA, $hex2BinIv);

        if (!$encrypt) {
            /** @var string $message */
            $message = openssl_error_string();

            throw new AESException($message, 500);
        }

        if (is_array($this->values)) {
            $this->values[$key] = base64_encode($encrypt);
        }

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function decode(array $rows): AES
    {
        foreach ($rows as $key => $row) {
            /** @var string $method */
            $method = $this->config['method'];

            /** @var string $passphrase */
            $passphrase = $this->config['passphrase'];

            /** @var string $hex2BinPassphrase */
            $hex2BinPassphrase = hex2bin($passphrase);

            /** @var string $iv */
            $iv = $this->config['iv'];

            /** @var string $hex2BinIv */
            $hex2BinIv = hex2bin($iv);

            /** @var string $decrypt */
            $decrypt = openssl_decrypt(base64_decode($row), $method, $hex2BinPassphrase, OPENSSL_RAW_DATA, $hex2BinIv);

            if (is_array($this->values)) {
                $this->values[$key] = $decrypt;
            }
        }

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
     * Add formatting to the defined algorithm
     *
     * @param string $key [AES algorithm type]
     *
     * @return string
     */
    private function formatCipherKey(string $key): string
    {
        return trim(strtolower($key));
    }

    /**
     * Get length of certain encryption method
     *
     * @param string $key [AES algorithm type]
     *
     * @return int
     *
     * @throws Exception [If the algorithm is not supported]
     */
    public function cipherKeyLength(string $key): int
    {
        return match ($this->formatCipherKey($key)) {
            self::AES_256_CBC => 32,
            default => throw new Exception("The algorithm is not supported", 500),
        };
    }

    /**
     * Creates key and iv for aes encryption
     *
     * @param string $key [AES algorithm type]
     *
     * @return AES
     *
     * @throws Exception [If the algorithm is not supported]
     */
    public function create(string $key): AES
    {
        $length = $this->cipherKeyLength($key);

        $this->values = [
            'passphrase' => hash('sha256', md5(uniqid())),
            'key' => bin2hex(openssl_random_pseudo_bytes($length)),
            'iv' => bin2hex(openssl_random_pseudo_bytes(16)),
            'method' => $this->formatCipherKey($key),
        ];

        return $this;
    }
}
