<?php

declare(strict_types=1);

namespace Tests\Exceptions;

use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Test\Test;

class InvalidConfigExceptionTest extends Test
{
    public function testExceptionIsThrown(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionCode(500);
        $this->expectExceptionMessage("Invalid Config");

        throw new InvalidConfigException();
    }

    public function testExceptionMessageAndCode(): void
    {
        $exception = new InvalidConfigException("ERR", 500);

        $this->assertEquals("ERR", $exception->getMessage());
        $this->assertEquals(500, $exception->getCode());
    }
}
