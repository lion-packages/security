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
use UnexpectedValueException;

/**
 * Allows you to generate the required configuration for JWT tokens, has methods
 * that allow you to encrypt and decrypt data with JWT
 *
 * @package Lion\Security
 */
class JWT implements ConfigInterface
{
    /**
     * [Property that stores the values of any type of execution being
     * performed 'encode, decode']
     *
     * @var array|object|string $values
     */
    private array|object|string $values = [];

    /**
     * [Property that contains the configuration defined for JWT processes]
     *
     * @var array $configValues
     */
    private array $configValues = [];

    /**
     * [Defines the url of the server that generates the JWT]
     *
     * @var string $jwtServerUrl
     */
    private string $jwtServerUrl = 'http://127.0.0.1:8000';

    /**
     * [Defines the url of the site that uses the JWT]
     *
     * @var string $jwtServerUrlAud
     */
    private string $jwtServerUrlAud = 'http://127.0.0.1:5173';

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
     * */
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

        $this->configValues = $config;

        return $this;
    }

    /**
     * {@inheritdoc}
     * */
    public function get(): array|object|string
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
        $this->configValues = [];
        $this->jwtServerUrl = 'http://127.0.0.1:8000';
        $this->jwtServerUrlAud = 'http://127.0.0.1:5173';
        $this->jwtExp = 3600;
        $this->jwtDefaultMD = 'RS256';
    }

    /**
     * Run the encryption/decryption process
     *
     * @param  Closure $executeFunction [Execute a function using exceptions]
     *
     * @return void
     */
    private function execute(Closure $executeFunction): void
    {
        try {
            $this->values = $executeFunction();
        } catch (InvalidArgumentException $e) {
            $this->values = (object) ['status' => 'error', 'message' => $e->getMessage()];
        } catch (DomainException $e) {
            $this->values = (object) ['status' => 'error', 'message' => $e->getMessage()];
        } catch (SignatureInvalidException $e) {
            $this->values = (object) ['status' => 'error', 'message' => $e->getMessage()];
        } catch (BeforeValidException $e) {
            $this->values = (object) ['status' => 'error', 'message' => $e->getMessage()];
        } catch (ExpiredException $e) {
            $this->values = (object) ['status' => 'error', 'message' => $e->getMessage()];
        } catch (UnexpectedValueException $e) {
            $this->values = (object) ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    /**
     * Encrypt data with defined settings
     *
     * @param  array $data [List of data to encrypt]
     * @param  int $time [Validity time]
     * @param  int $bytes [Number of bits]
     *
     * @return JWT
     */
    public function encode(array $data, int $time = 0, int $bytes = 16): JWT
    {
        $this->execute(function() use ($data, $time, $bytes) {
            if (empty($this->configValues['privateKey'])) {
                throw new InvalidConfigException('The privateKey has not been defined');
            }

            $now = strtotime('now');

            $config = [
                'iss' => $this->jwtServerUrl,
                'aud' => $this->jwtServerUrlAud,
                'jti' => base64_encode(random_bytes($bytes)),
                'iat' => $now,
                'nbf' => $now,
                'exp' => $now + (0 === $time ? ((int) $this->jwtExp) : $time),
                'data' => $data
            ];

            return FBJWT::encode($config, $this->configValues['privateKey'], $this->jwtDefaultMD);
        });

        return $this;
    }

    /**
     * Decodes the data with the defined settings
     *
     * @param  string $jwt [Json web token]
     *
     * @return JWT
     */
    public function decode(?string $jwt = ''): JWT
    {
        $this->execute(function() use ($jwt) {
            if (empty($this->configValues['publicKey'])) {
                throw new InvalidConfigException('The publicKey has not been defined');
            }

            if (in_array($jwt, ['null', null, ''], true)) {
                return (object) ['status' => 'error', 'message' => 'The JWT does not exist'];
            }

            return FBJWT::decode($jwt, new Key($this->configValues['publicKey'], $this->jwtDefaultMD));
        });

        return $this;
    }

    /**
     * Modify the serverUrl to generate the token
     *
     * @param  string $jwtServerUrl [Server URL for the token]
     *
     * @return JWT
     */
    public function jwtServerUrl(string $jwtServerUrl): JWT
    {
        $this->jwtServerUrl = $jwtServerUrl;

        return $this;
    }

    /**
     * Modify the serverUrlAud to generate the token
     *
     * @param  string $jwtServerUrlAud [Auxiliary URL of the site that uses it
     * for the token]
     *
     * @return JWT
     */
    public function jwtServerUrlAud(string $jwtServerUrlAud): JWT
    {
        $this->jwtServerUrlAud = $jwtServerUrlAud;

        return $this;
    }

    /**
     * Modify the exp to generate the token
     *
     * @param  int $jwtExp [Validity time]
     *
     * @return JWT
     */
    public function jwtExp(int $jwtExp): JWT
    {
        $this->jwtExp = $jwtExp;

        return $this;
    }

    /**
     * Modify the defaultMD to generate the token
     *
     * @param  int $jwtDefaultMD [Encryption protocol]
     *
     * @return JWT
     */
    public function jwtDefaultMD(int $jwtDefaultMD): JWT
    {
        $this->jwtDefaultMD = $jwtDefaultMD;

        return $this;
    }

    /**
     * Gets the HTTP_AUTHORIZATION header token
     *
     * @return string|bool
     */
    public function getJWT(): string|bool
    {
        $headers = $_SERVER;

        if (isset($headers['HTTP_AUTHORIZATION'])) {
            if (preg_match('/Bearer\s(\S+)/', $headers['HTTP_AUTHORIZATION'], $matches)) {
                return $matches[1];
            }
        }

        return false;
    }
}
