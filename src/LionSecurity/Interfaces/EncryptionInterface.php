<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

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
     * @param string $key [Key of the word to be encrypted]
     * @param string $value [Value of the word to be encrypted]
     *
     * @return EncryptionInterface
     */
    public function encode(string $key, string $value): EncryptionInterface;

    /**
     * Decodes the data with the defined settings
     *
     * @param array<string, string> $rows [list of decrypted items]
     *
     * @return EncryptionInterface
     */
    public function decode(array $rows): EncryptionInterface;
}
