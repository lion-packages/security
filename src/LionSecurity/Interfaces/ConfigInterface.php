<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use OpenSSLAsymmetricKey;

/**
 * Represents the implementation for configuring encryption processes.
 */
interface ConfigInterface
{
    /**
     * Define settings
     *
     * RSA:
     *
     * * key
     * * urlPath
     * * rsaConfig
     * * rsaPrivateKeyBits
     * * rsaDefaultMd
     *
     * AES:
     *
     * * key
     *
     * JWT:
     *
     * * key
     * * jwtServerUrl
     * * jwtServerUrlAud
     * * jwtExp
     * * jwtDefaultMD
     * * privateKey
     * * publicKey
     *
     * @param array{
     *     key: string|OpenSSLAsymmetricKey|null,
     *     urlPath?: string,
     *     rsaConfig?: string,
     *     rsaPrivateKeyBits?: int,
     *     rsaDefaultMd?: string,
     *     jwtServerUrl?: string,
     *     jwtServerUrlAud?: string,
     *     jwtExp?: int,
     *     jwtDefaultMD?: string
     * } $config Configuration data list.
     *
     * @return ConfigInterface
     */
    public function config(array $config): ConfigInterface;
}
