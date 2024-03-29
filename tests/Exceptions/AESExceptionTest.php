<?php

declare(strict_types=1);

namespace Tests\Exceptions;

use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Test\Test;

class AESExceptionTest extends Test
{
    public function testExceptionIsThrown(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage("Invalid Config");

        throw new InvalidConfigException();
    }

    public function testExceptionMessageAndCode(): void
    {
        $exception = new InvalidConfigException("Custom message", 500);

        $this->assertEquals("Custom message", $exception->getMessage());
        $this->assertEquals(500, $exception->getCode());
    }
}
