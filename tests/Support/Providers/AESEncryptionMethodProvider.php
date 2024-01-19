<?php

declare(strict_types=1);

namespace Tests\Support\Providers;

use Lion\Security\AES;

trait AESEncryptionMethodProvider
{
    public static function AESEncryptionMethodProvider(): array
    {
        return [
            [AES::AES_128_CBC, 16],
            [AES::AES_128_CBC_CTS, 16],
            [AES::AES_128_CBC_HMAC_SHA1, 16],
            [AES::AES_128_CBC_HMAC_SHA256, 16],
            [AES::AES_128_CCM, 16],
            [AES::AES_128_CFB, 16],
            [AES::AES_128_CFB1, 16],
            [AES::AES_128_CFB8, 16],
            [AES::AES_128_CTR, 16],
            [AES::AES_128_ECB, 16],
            [AES::AES_128_GCM, 16],
            [AES::AES_128_OCB, 16],
            [AES::AES_128_OFB, 16],
            [AES::AES_128_SIV, 16],
            [AES::AES_128_WRAP, 16],
            [AES::AES_128_WRAP_INV, 16],
            [AES::AES_128_WRAP_PAD, 16],
            [AES::AES_128_WRAP_PAD_INV, 16],
            [AES::AES_128_XTS, 16],
            [AES::AES_192_CBC, 24],
            [AES::AES_192_CBC_CTS, 24],
            [AES::AES_192_CCM, 24],
            [AES::AES_192_CFB, 24],
            [AES::AES_192_CFB1, 24],
            [AES::AES_192_CFB8, 24],
            [AES::AES_192_CTR, 24],
            [AES::AES_192_ECB, 24],
            [AES::AES_192_GCM, 24],
            [AES::AES_192_OCB, 24],
            [AES::AES_192_OFB, 24],
            [AES::AES_192_SIV, 24],
            [AES::AES_192_WRAP, 24],
            [AES::AES_192_WRAP_INV, 24],
            [AES::AES_192_WRAP_PAD, 24],
            [AES::AES_192_WRAP_PAD_INV, 24],
            [AES::AES_256_CBC, 32],
            [AES::AES_256_CBC_CTS, 32],
            [AES::AES_256_CBC_HMAC_SHA1, 32],
            [AES::AES_256_CBC_HMAC_SHA256, 32],
            [AES::AES_256_CCM, 32],
            [AES::AES_256_CFB, 32],
            [AES::AES_256_CFB1, 32],
            [AES::AES_256_CFB8, 32],
            [AES::AES_256_CTR, 32],
            [AES::AES_256_ECB, 32],
            [AES::AES_256_GCM, 32],
            [AES::AES_256_OCB, 32],
            [AES::AES_256_OFB, 32],
            [AES::AES_256_SIV, 32],
            [AES::AES_256_WRAP, 32],
            [AES::AES_256_WRAP_INV, 32],
            [AES::AES_256_WRAP_PAD, 32],
            [AES::AES_256_WRAP_PAD_INV, 32],
            [AES::AES_256_XTS, 32],
        ];
    }
}
