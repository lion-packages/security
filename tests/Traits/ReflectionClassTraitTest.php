<?php

declare(strict_types=1);

namespace Tests\Traits;

use LionSecurity\AES;
use LionSecurity\Traits\ReflectionClassTrait;
use PHPUnit\Framework\TestCase;

class ReflectionClassTraitTest extends TestCase
{
    use ReflectionClassTrait;

    private AES $aes;

    protected function setUp(): void
    {
        $this->aes = new AES();
    }

    public function testGetPrivateProperty(): void
    {
        $this->init($this->aes);
        $this->aes->key('sleon-key-012345');

        $this->assertEquals('sleon-key-012345', $this->getPrivateProperty('key'));
    }
}
