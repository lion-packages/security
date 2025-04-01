<?php

declare(strict_types=1);

namespace Tests\Providers;

use Lion\Security\AES;

trait AESEncryptionMethodProvider
{
    /**
     * @return array<int, array<string, int|string>>
     */
    public static function AESEncryptionMethodProvider(): array
    {
        return [
            [
                'method' => AES::AES_256_CBC,
                'bits' => 32,
                'returnKey' => AES::AES_256_CBC,
            ],
            [
                'method' => strtoupper(AES::AES_256_CBC),
                'bits' => 32,
                'returnKey' => AES::AES_256_CBC,
            ],
            [
                'method' => (' ' . strtoupper(AES::AES_256_CBC) . ' '),
                'bits' => 32,
                'returnKey' => AES::AES_256_CBC,
            ],
        ];
    }

    /**
     * @return array<int, array{
     *     method: string,
     *     returnKey: string
     * }>
     */
    public static function formatCipherKeyProvider(): array
    {
        return [
            [
                'method' => AES::AES_256_CBC,
                'returnKey' => AES::AES_256_CBC,
            ],
            [
                'method' => strtoupper(AES::AES_256_CBC),
                'returnKey' => AES::AES_256_CBC,
            ],
            [
                'method' => (' ' . strtoupper(AES::AES_256_CBC) . ' '),
                'returnKey' => AES::AES_256_CBC,
            ],
        ];
    }
}
