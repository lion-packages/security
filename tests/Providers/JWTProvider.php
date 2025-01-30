<?php

declare(strict_types=1);

namespace Tests\Providers;

trait JWTProvider
{
    /**
     * @return array<int, array<string, string|null>>
     */
    public static function nullJwtDataProvider(): array
    {
        return [
            [
                'value' => null,
            ],
            [
                'value' => 'null',
            ],
            [
                'value' => '',
            ],
        ];
    }
}
