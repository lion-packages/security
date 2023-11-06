<?php

declare(strict_types=1);

namespace LionSecurity\Traits;

trait FilesTrait
{
    private function rmdirRecursively(string $dir): void
    {
        if (is_dir($dir)) {
            $objects = scandir($dir);

            foreach ($objects as $object) {
                if ($object != "." && $object != "..") {
                    if (is_dir($dir.'/'.$object)) {
                        $this->rmdirRecursively($dir . '/' . $object);
                    } else {
                        unlink($dir . '/' . $object);
                    }
                }
            }

            rmdir($dir);
        }
    }

    private function createDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0777, true)) {
                throw new \RuntimeException("No se pudo crear el directorio: $directory");
            }
        }
    }
}
