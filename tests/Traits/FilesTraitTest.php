<?php

declare(strict_types=1);

namespace Tests\Traits;

use LionSecurity\Traits\FilesTrait;
use PHPUnit\Framework\TestCase;

class FilesTraitTest extends TestCase
{
    use FilesTrait;

    const URL_PATH_EXAMPLE = './storage/example/';

    public function testRmdirRecursively(): void
    {
        $this->createDirectory(self::URL_PATH_EXAMPLE);
        $this->rmdirRecursively(self::URL_PATH_EXAMPLE);

        $this->assertFalse(is_dir(self::URL_PATH_EXAMPLE));
    }

    public function testCreateDirectory(): void
    {
        $this->createDirectory(self::URL_PATH_EXAMPLE);

        $this->assertTrue(is_dir(self::URL_PATH_EXAMPLE));
    }
}
