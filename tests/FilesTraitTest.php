<?php

declare(strict_types=1);

use LionSecurity\Traits\FilesTrait;
use PHPUnit\Framework\TestCase;

class FilesTraitTest extends TestCase
{
    use FilesTrait;

    public function testRmdirRecursively(): void
    {
        $directory = './storage/example/';
        $this->createDirectory($directory);
        $this->rmdirRecursively($directory);

        $this->assertFalse(is_dir($directory));
    }

    public function testCreateDirectory(): void
    {
        $directory = './storage/example/';
        $this->createDirectory($directory);

        $this->assertTrue(is_dir($directory));
    }
}
