<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use OpenSSLAsymmetricKey;

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
     * * passphrase
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
     * * privateKey
     * * publicKey
     *
     * @param array{
     *     urlPath?: string,
     *     rsaConfig?: string,
     *     rsaPrivateKeyBits?: int,
     *     rsaDefaultMd?: string,
     *     passphrase?: string,
     *     key?: string,
     *     iv?: string,
     *     method?: string,
     *     jwtServerUrl?: string,
     *     jwtServerUrlAud?: string,
     *     jwtExp?: int,
     *     jwtDefaultMD?: string,
     *     privateKey?: OpenSSLAsymmetricKey|string,
     *     publicKey?: OpenSSLAsymmetricKey|string
     * } $config [Configuration data list]
     *
     * @return ConfigInterface
     */
    public function config(array $config): ConfigInterface;
}
