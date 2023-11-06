<?php

declare(strict_types=1);

namespace LionSecurity;

use Closure;
use DomainException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\Key;
use Firebase\JWT\JWT as FBJWT;
use InvalidArgumentException;
use LionSecurity\Exceptions\InvalidConfigException;
use LionSecurity\RSA;
use UnexpectedValueException;

class JWT
{
    const RSA = 'RSA';
    const AES = 'AES';
    const METHODS = [self::RSA, self::AES];

    private RSA $rsa;
    private AES $aes;

    private array|object|string $values = [];
    private array $configValues = [];
    private string $jwtServerUrl = 'http://127.0.0.1:8000';
    private string $jwtServerUrlAud = 'http://127.0.0.1:5173';
    private int $jwtExp = 3600;
    private string $jwtDefaultMD = 'RS256';

    public function __construct()
    {
        $this->rsa = new RSA();
        $this->aes = new AES();
    }

    /**
     * Clear variables so they have their original value
     * */
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
     * Define settings for AES encryption
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
     * Run the encryption/decryption process
     * */
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
     * */
    public function encode(array $data, int $time = 0, int $bytes = 16): JWT
    {
        $this->execute(function() use ($data, $time, $bytes) {
            if (empty($this->configValues['privateKey'])) {
                throw new InvalidConfigException('The privateKey has not been defined');
            }

            $now = strtotime("now");

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
     * */
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
     * */
    public function jwtServerUrl(string $jwtServerUrl): JWT
    {
        $this->jwtServerUrl = $jwtServerUrl;

        return $this;
    }

    /**
     * Modify the serverUrlAud to generate the token
     * */
    public function jwtServerUrlAud(string $jwtServerUrlAud): JWT
    {
        $this->jwtServerUrlAud = $jwtServerUrlAud;

        return $this;
    }

    /**
     * Modify the exp to generate the token
     * */
    public function jwtExp(int $jwtExp): JWT
    {
        $this->jwtExp = $jwtExp;

        return $this;
    }

    /**
     * Modify the defaultMD to generate the token
     * */
    public function jwtDefaultMD(int $jwtDefaultMD): JWT
    {
        $this->jwtDefaultMD = $jwtDefaultMD;

        return $this;
    }

    /**
     * Gets the Authorization header token
     * */
    public function getJWT(): string|bool
    {
        if (isset($_SERVER['Authorization'])) {
            if (preg_match('/Bearer\s(\S+)/', $_SERVER['Authorization'], $matches)) {
                return $matches[1];
            }
        }

        return false;
    }

    /**
     * Returns the current array/object with the encrypted/decrypted data
     * */
    public function get(): array|object|string
    {
        $values = $this->values;
        $this->clean();

        return $values;
    }
}
