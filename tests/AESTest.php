<?php

namespace Tests;

use LionSecurity\AES;
use PHPUnit\Framework\TestCase;

class AESTest extends TestCase
{
    private AES $aes;

    public function testCipherKeyLength(): void
    {
        $lenght = $this->aes->cipherKeyLength(AES::AES_256_CBC);

        $this->assertIsInt($lenght);
        $this->assertSame(32, $lenght);
    }

    public function testCipherKeyLengthNotExist(): void
    {
        $lenght = $this->aes->cipherKeyLength(uniqid());

        $this->assertIsBool($lenght);
        $this->assertFalse($lenght);
    }

    public function setUp(): void
    {
        $this->aes = new AES();
    }
}
