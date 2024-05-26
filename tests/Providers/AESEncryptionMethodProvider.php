<?php

declare(strict_types=1);

namespace Tests\Providers;

use Lion\Security\AES;

trait AESEncryptionMethodProvider
{
    public static function AESEncryptionMethodProvider(): array
    {
        return [
            [
                'method' => AES::AES_256_CBC,
                'bits' => 32,
            ],
        ];
    }
}
