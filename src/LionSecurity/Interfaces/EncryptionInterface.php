<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use Lion\Security\AES;
use Lion\Security\JWT;
use Lion\Security\RSA;

/**
 * Represents the implementation of methods for encryption and decryption
 *
 * @package Lion\Security\Interfaces
 */
interface EncryptionInterface
{
    /**
     * Encrypt data with defined settings
     *
     * @param  string $key [Key of the word to be encrypted]
     * @param  string $value [Value of the word to be encrypted]
     *
     * @return AES|JWT|RSA
     */
    public function encode(string $key, string $value): AES|JWT|RSA;

    /**
     * Decodes the data with the defined settings
     *
     * @param  array $rows [list of decrypted items]
     *
     * @return AES|JWT|RSA
     */
    public function decode(array $rows): AES|JWT|RSA;
}
