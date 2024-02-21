<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use Lion\Security\AES;
use Lion\Security\JWT;
use Lion\Security\RSA;

interface EncryptionInterface
{
    /**
     * Encrypt data with defined settings
     *
     * @param  string $key [key of the word to be encrypted]
     * @param  string $value [value of the word to be encrypted]
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
