<?php

declare(strict_types=1);

namespace Tests\Exceptions;

use Lion\Security\Exceptions\AESException;
use Lion\Test\Test;

class AESExceptionTest extends Test
{
    public function testExceptionIsThrown(): void
    {
        $this->expectException(AESException::class);
        $this->expectExceptionCode(500);
        $this->expectExceptionMessage("ERR");

        throw new AESException('ERR');
    }

    public function testExceptionMessageAndCode(): void
    {
        $exception = new AESException("ERR", 500);

        $this->assertSame("ERR", $exception->getMessage());
        $this->assertSame(500, $exception->getCode());
    }
}
