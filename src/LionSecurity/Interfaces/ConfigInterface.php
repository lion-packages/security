<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use Lion\Security\AES;
use Lion\Security\JWT;
use Lion\Security\RSA;

/**
 * Represents the implementation for configuring encryption processes
 *
 * @package Lion\Security\Interfaces
 */
interface ConfigInterface
{
    /**
     * Define settings
     *
     * RSA:
     *
     * * urlPath
     * * rsaConfig
     * * rsaPrivateKeyBits
     * * rsaDefaultMd
     *
     * AES:
     *
     * * key
     * * iv
     * * method
     *
     * JWT:
     *
     * * jwtServerUrl
     * * jwtServerUrlAud
     * * jwtExp
     * * jwtDefaultMD
     *
     * @param  array $config [Configuration data list]
     *
     * @return AES|JWT|RSA
     */
    public function config(array $config): AES|JWT|RSA;

    /**
     * Returns the current array/object with the generated data
     *
     * @return array|object|string
     */
    public function get(): array|object|string;
}
