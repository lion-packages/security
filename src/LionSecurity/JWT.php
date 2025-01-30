<?php

declare(strict_types=1);

namespace Lion\Security;

use Closure;
use DomainException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\Key;
use Firebase\JWT\JWT as FBJWT;
use InvalidArgumentException;
use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\Interfaces\ConfigInterface;
use OpenSSLAsymmetricKey;
use stdClass;
use UnexpectedValueException;

/**
 * Allows you to generate the required configuration for JWT tokens, has methods
 * that allow you to encrypt and decrypt data with JWT
 *
 * @property array<string, string>|stdClass|string $values [Property that stores
 * the values of any type of execution being performed 'encode, decode']
 * @property array<string, int|string|OpenSSLAsymmetricKey> $config [Property
 * that contains the configuration defined for JWT processes]
 * @property string $jwtServerUrl [Defines the url of the server that generates
 * the JWT]
 * @property string $jwtServerUrlAud [Defines the url of the site that uses the
 * JWT]
 * @property int $jwtExp [Stores the lifetime of the JWT]
 * @property string $jwtDefaultMD [Sets the default signing algorithm]
 *
 * @package Lion\Security
 */
class JWT implements ConfigInterface
{
    /**
     * [Property that stores the values of any type of execution being
     * performed 'encode, decode']
     *
     * @var array<string, string>|stdClass|string $values
     */
    private array|stdClass|string $values = [];

    /**
     * [Property that contains the configuration defined for JWT processes]
     *
     * @var array<string, int|string|OpenSSLAsymmetricKey> $config
     */
    private array $config = [];

    /**
     * [Defines the url of the server that generates the JWT]
     *
     * @var string $jwtServerUrl
     */
    private string $jwtServerUrl = 'http://localhost:8000';

    /**
     * [Defines the url of the site that uses the JWT]
     *
     * @var string $jwtServerUrlAud
     */
    private string $jwtServerUrlAud = 'http://localhost:5173';

    /**
     * [Stores the lifetime of the JWT]
     *
     * @var int $jwtExp
     */
    private int $jwtExp = 3600;

    /**
     * [Sets the default signing algorithm]
     *
     * @var string $jwtDefaultMD
     */
    private string $jwtDefaultMD = 'RS256';

    /**
     * {@inheritdoc}
     */
    public function config(array $config): JWT
    {
        if (!empty($config['jwtServerUrl'])) {
            $this->jwtServerUrl = $config['jwtServerUrl'];
        }

        if (!empty($config['jwtServerUrlAud'])) {
            $this->jwtServerUrlAud = $config['jwtServerUrlAud'];
        }

        if (!empty($config['jwtExp'])) {
            $this->jwtExp = $config['jwtExp'];
        }

        if (!empty($config['jwtDefaultMD'])) {
            $this->jwtDefaultMD = $config['jwtDefaultMD'];
        }

        $this->config = $config;

        return $this;
    }

    /**
     * Returns the current array/object with the generated data
     *
     * @return array<string, string>|stdClass|string
     */
    public function get(): array|stdClass|string
    {
        $values = $this->values;

        $this->clean();

        return $values;
    }

    /**
     * Clear variables so they have their original value
     *
     * @return void
     */
    private function clean(): void
    {
        $this->values = [];

        $this->config = [];

        $this->jwtServerUrl = 'http://localhost:8000';

        $this->jwtServerUrlAud = 'http://localhost:5173';

        $this->jwtExp = 3600;

        $this->jwtDefaultMD = 'RS256';
    }

    /**
     * Run the encryption/decryption process
     *
     * @param Closure $executeFunction [Execute a function using exceptions]
     *
     * @return void
     */
    private function execute(Closure $executeFunction): void
    {
        try {
            /** @var string|stdClass $return */
            $return = $executeFunction();

            $this->values = $return;
        } catch (
            BeforeValidException |
            DomainException |
            ExpiredException |
            InvalidArgumentException |
            InvalidConfigException |
            SignatureInvalidException |
            UnexpectedValueException $e
        ) {
            $this->values = (object) [
                'code' => $e->getCode(),
                'status' => 'error',
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Encrypt data with defined settings
     *
     * @param array<string, mixed> $data [List of data to encrypt]
     * @param int $time [Validity time]
     * @param int $bytes [Number of bits]
     *
     * @return JWT
     */
    public function encode(array $data, int $time = 0, int $bytes = 16): JWT
    {
        $this->execute(function () use ($data, $time, $bytes): string {
            if (empty($this->config['privateKey'])) {
                throw new InvalidConfigException('The privateKey has not been defined', 500);
            }

            $now = strtotime('now');

            $config = [
                'iss' => $this->jwtServerUrl,
                'aud' => $this->jwtServerUrlAud,
                'jti' => base64_encode(random_bytes(max(1, $bytes))),
                'iat' => $now,
                'nbf' => $now,
                'exp' => $now + (0 === $time ? $this->jwtExp : $time),
                'data' => $data,
            ];

            if (
                !is_string($this->config['privateKey']) &&
                !$this->config['privateKey'] instanceof OpenSSLAsymmetricKey
            ) {
                throw new InvalidConfigException(
                    'The privateKey must be a string or an OpenSSLAsymmetricKey instance.',
                    500
                );
            }

            return FBJWT::encode($config, $this->config['privateKey'], $this->jwtDefaultMD);
        });

        return $this;
    }

    /**
     * Decodes the data with the defined settings
     *
     * @param string|null $jwt [Json web token]
     *
     * @return JWT
     */
    public function decode(?string $jwt): JWT
    {
        $this->execute(function () use ($jwt): stdClass {
            if (empty($this->config['publicKey'])) {
                throw new InvalidConfigException('The publicKey has not been defined', 500);
            }

            if (in_array($jwt, ['null', null, ''], true)) {
                throw new InvalidConfigException('The JWT does not exist', 500);
            }

            if (
                !is_string($this->config['publicKey']) &&
                !$this->config['publicKey'] instanceof OpenSSLAsymmetricKey
            ) {
                throw new InvalidConfigException(
                    'The publicKey must be a string or an OpenSSLAsymmetricKey instance.',
                    500
                );
            }

            return FBJWT::decode($jwt, new Key($this->config['publicKey'], $this->jwtDefaultMD));
        });

        return $this;
    }

    /**
     * Defines the type of encryption
     *
     * @param RSA $rsa [Allows you to generate the required configuration for
     * public and private keys, has methods that allow you to encrypt and
     * decrypt data with RSA]
     *
     * @return JWT
     */
    public function setEncryptionMethod(RSA $rsa): JWT
    {
        $rsa->init();

        $publicKey = $rsa->getPublicKey();

        if ($publicKey instanceof OpenSSLAsymmetricKey) {
            $this->config['publicKey'] = $publicKey;
        }

        $privateKey = $rsa->getPrivateKey();

        if ($privateKey instanceof OpenSSLAsymmetricKey) {
            $this->config['privateKey'] = $privateKey;
        }

        return $this;
    }

    /**
     * Gets the HTTP_AUTHORIZATION header token
     *
     * @return string|bool
     */
    public function getJWT(): string|bool
    {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            /** @var string $token */
            $token = $_SERVER['HTTP_AUTHORIZATION'];

            if (preg_match('/Bearer\s(\S+)/', $token, $matches)) {
                return $matches[1];
            }
        }

        return false;
    }
}
