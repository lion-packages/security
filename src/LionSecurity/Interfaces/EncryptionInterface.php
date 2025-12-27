<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use Lion\Security\Exceptions\AESException;

/**
 * Represents the implementation of methods for encryption and decryption.
 */
interface EncryptionInterface
{
    /**
     * Encrypt data with defined settings.
     *
     * @param array<string, float|int|string> $data Data encrypted in a single
     * block.
     *
     * @return EncryptionInterface
     *
     * @throws AESException This class represents custom exceptions for AES class
     * processes.
     */
    public function encode(array $data): EncryptionInterface;

    /**
     * Decodes the data with the defined settings.
     *
     * @param array<string, string> $encrypted Encrypted data block.
     *
     * @return EncryptionInterface
     *
     * @throws AESException This class represents custom exceptions for AES class
     * processes.
     */
    public function decode(array $encrypted): EncryptionInterface;
}
