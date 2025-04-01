<?php

declare(strict_types=1);

namespace Tests;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Lion\Security\AES;
use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\JWT;
use Lion\Security\RSA;
use Lion\Test\Test;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test as Testing;
use ReflectionException;
use stdClass;
use Tests\Providers\JWTProvider;

class JWTTest extends Test
{
    use JWTProvider;

    private const string JWT_SERVER_URL = 'http://localhost:8000';
    private const string JWT_SERVER_URL_AUD = 'http://localhost:5173';
    private const int JWT_EXP = 3600;
    private const string JWT_DEFAULT_MD = 'RS256';
    private const string JWT_DEFAULT_MD_AES = 'HS256';
    private const array CONFIG_JWT_RSA = [
        'jwtServerUrl' => self::JWT_SERVER_URL,
        'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
        'jwtExp' => self::JWT_EXP,
        'jwtDefaultMD' => self::JWT_DEFAULT_MD
    ];
    private const array CONFIG_JWT_AES = [
        'jwtServerUrl' => self::JWT_SERVER_URL,
        'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
        'jwtExp' => self::JWT_EXP,
        'jwtDefaultMD' => 'HS256'
    ];
    private const string URL_PATH = './storage/keys/';
    private const string RSA_CONFIG = '/etc/ssl/openssl.cnf';
    private const int RSA_PRIVATE_KEY_BITS = 2048;
    private const string RSA_DEFAULT_MD = 'sha256';
    private const array CONFIG_RSA = [
        'urlPath' => self::URL_PATH,
        'rsaConfig' => self::RSA_CONFIG,
        'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
        'rsaDefaultMd' => self::RSA_DEFAULT_MD
    ];
    private const string KEY = '0123456789sleon4';

    private JWT $jwt;
    private RSA $rsa;
    private AES $aes;

    /**
     * @throws ReflectionException
     */
    protected function setUp(): void
    {
        $this->rsa = new RSA();

        $this->jwt = new JWT();

        $this->aes = new AES();

        $this->initReflection($this->jwt);

        $this->createDirectory(self::URL_PATH);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursively('./storage/');
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function config(): void
    {
        $this->jwt->config(self::CONFIG_JWT_RSA);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingJwtServerUrl(): void
    {
        $this->jwt->config([
            'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
            'jwtExp' => self::JWT_EXP,
            'jwtDefaultMD' => self::JWT_DEFAULT_MD
        ]);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingJwtServerUrlAud(): void
    {
        $this->jwt->config([
            'jwtServerUrl' => self::JWT_SERVER_URL,
            'jwtExp' => self::JWT_EXP,
            'jwtDefaultMD' => self::JWT_DEFAULT_MD
        ]);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingJwtExp(): void
    {
        $this->jwt->config([
            'jwtServerUrl' => self::JWT_SERVER_URL,
            'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
            'jwtDefaultMD' => self::JWT_DEFAULT_MD
        ]);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingJwtDefaultMD(): void
    {
        $this->jwt->config([
            'jwtServerUrl' => self::JWT_SERVER_URL,
            'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
            'jwtExp' => self::JWT_EXP
        ]);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function encodeWithRSA(): void
    {
        $this->rsa
            ->config(self::CONFIG_RSA)
            ->create();

        /** @var OpenSSLAsymmetricKey $privateKey */
        $privateKey = $this->rsa->getPrivateKey();

        $encode = $this->jwt
            ->config([
                'privateKey' => $privateKey,
            ])
            ->encode([
                'key' => 'value',
            ])
            ->get();

        $this->assertIsString($encode);

        /** @var OpenSSLAsymmetricKey $publicKey */
        $publicKey = $this->rsa
            ->getPublicKey();

        $decode = $this->jwt
            ->config([
                'publicKey' => $publicKey,
            ])
            ->decode($encode)
            ->get();

        $this->assertIsObject($decode);
        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('iss', $decode);
        $this->assertObjectHasProperty('aud', $decode);
        $this->assertObjectHasProperty('jti', $decode);
        $this->assertObjectHasProperty('iat', $decode);
        $this->assertObjectHasProperty('nbf', $decode);
        $this->assertObjectHasProperty('exp', $decode);
        $this->assertObjectHasProperty('data', $decode);
    }

    #[Testing]
    public function encodeWithAES(): void
    {
        $encode = $this->jwt
            ->config([
                'privateKey' => self::KEY,
                ...self::CONFIG_JWT_AES
            ])
            ->encode([
                'key' => 'value',
            ])
            ->get();

        $this->assertIsString($encode);

        $decode = $this->jwt
            ->config([
                'publicKey' =>  self::KEY,
                ...self::CONFIG_JWT_AES
            ])
            ->decode($encode)
            ->get();

        $this->assertIsObject($decode);
        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('iss', $decode);
        $this->assertObjectHasProperty('aud', $decode);
        $this->assertObjectHasProperty('jti', $decode);
        $this->assertObjectHasProperty('iat', $decode);
        $this->assertObjectHasProperty('nbf', $decode);
        $this->assertObjectHasProperty('exp', $decode);
        $this->assertObjectHasProperty('data', $decode);
    }

    #[Testing]
    public function encodeWithMissingPrivateKey(): void
    {
        $encode = $this->jwt
            ->config([])
            ->encode([
                'key' => 'value',
            ])
            ->get();

        $this->assertInstanceOf(stdClass::class, $encode);
        $this->assertObjectHasProperty('code', $encode);
        $this->assertObjectHasProperty('status', $encode);
        $this->assertObjectHasProperty('message', $encode);
        $this->assertSame(500, $encode->code);
        $this->assertSame('error', $encode->status);
        $this->assertSame('The privateKey has not been defined', $encode->message);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function decodeWithRSAValidJWT(): void
    {
        $this->rsa
            ->config(self::CONFIG_RSA)
            ->create();

        /** @var OpenSSLAsymmetricKey $privateKey */
        $privateKey = $this->rsa->getPrivateKey();

        $jwt = $this->jwt
            ->config([
                'privateKey' => $privateKey,
            ])->encode([
                'key' => 'value',
            ], 3600)
            ->get();

        $this->assertIsString($jwt);

        /** @var OpenSSLAsymmetricKey $publicKey */
        $publicKey = $this->rsa->getPublicKey();

        $decode = $this->jwt
            ->config([
                'publicKey' => $publicKey,
            ])
            ->decode($jwt)
            ->get();

        $this->assertIsObject($decode);
        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('data', $decode);
        $this->assertIsObject($decode->data);
        $this->assertInstanceOf(stdClass::class, $decode->data);
        $this->assertObjectHasProperty('key', $decode->data);
        $this->assertSame('value', $decode->data->key);
    }

    /**
     * @throws Exception
     */
    #[Testing]
    public function decodeWithAESValidJWT(): void
    {
        /** @var stdClass $config */
        $config = $this->aes
            ->create(AES::AES_256_CBC)
            ->toObject()
            ->get();

        /** @var string $key */
        $key = $config->key;

        $jwt = $this->jwt
            ->config([
                'jwtDefaultMD' => self::JWT_DEFAULT_MD_AES,
                'privateKey' => $key,
            ])
            ->encode([
                'key' => 'value',
            ], 3600)
            ->get();

        $this->assertIsString($jwt);

        $decode = $this->jwt
            ->config([
                'jwtDefaultMD' => self::JWT_DEFAULT_MD_AES,
                'publicKey' => $key,
            ])
            ->decode($jwt)
            ->get();

        $this->assertIsObject($decode);
        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('data', $decode);
        $this->assertIsObject($decode->data);
        $this->assertInstanceOf(stdClass::class, $decode->data);
        $this->assertObjectHasProperty('key', $decode->data);
        $this->assertSame('value', $decode->data->key);
    }

    #[Testing]
    public function decodeWithMissingPublicKey(): void
    {
        $decode = $this->jwt
            ->config([])
            ->decode(null)
            ->get();

        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('code', $decode);
        $this->assertObjectHasProperty('status', $decode);
        $this->assertObjectHasProperty('message', $decode);
        $this->assertSame(500, $decode->code);
        $this->assertSame('error', $decode->status);
        $this->assertSame('The publicKey has not been defined', $decode->message);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    #[DataProvider('nullJwtDataProvider')]
    public function decodeWithNullJwt(?string $value): void
    {
        /** @var OpenSSLAsymmetricKey $publicKey */
        $publicKey = $this->rsa
            ->config(self::CONFIG_RSA)
            ->create()
            ->getPublicKey();

        $decode = $this->jwt
            ->config([
                'publicKey' => $publicKey,
            ])
            ->decode($value)
            ->get();

        $this->assertIsObject($decode);
        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('code', $decode);
        $this->assertObjectHasProperty('status', $decode);
        $this->assertObjectHasProperty('message', $decode);
        $this->assertSame(500, $decode->code);
        $this->assertSame('error', $decode->status);
        $this->assertSame('The JWT does not exist', $decode->message);
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function jwtServerUrl(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function jwtServerUrlAud(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function jwtExp(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function jwtDefaultMD(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    /**
     * @throws GuzzleException
     * @throws InvalidConfigException
     */
    #[Testing]
    public function getJWTWithValidAuthorizationHeader(): void
    {
        $this->rsa
            ->config(self::CONFIG_RSA)
            ->create();

        /** @var OpenSSLAsymmetricKey $privateKey */
        $privateKey = $this->rsa->getPrivateKey();

        $jwt = $this->jwt
            ->config([
                'privateKey' => $privateKey,
            ])
            ->encode([
                'key' => 'value',
            ])
            ->get();

        $this->assertIsString($jwt);

        $getJwt = json_decode(
            new Client()
                ->get(self::JWT_SERVER_URL, [
                    'headers' => [
                        'Authorization' => "Bearer {$jwt}",
                    ],
                ])
                ->getBody()
                ->getContents()
        );

        $this->assertSame($jwt, $getJwt);

        /** @var OpenSSLAsymmetricKey $publicKey */
        $publicKey = $this->rsa->getPublicKey();

        $decode = $this->jwt
            ->config([
                'publicKey' => $publicKey,
            ])
            ->decode($getJwt)
            ->get();

        $this->assertIsObject($decode);
        $this->assertInstanceOf(stdClass::class, $decode);
        $this->assertObjectHasProperty('data', $decode);
        $this->assertIsObject($decode->data);
        $this->assertInstanceOf(stdClass::class, $decode->data);
        $this->assertObjectHasProperty('key', $decode->data);
        $this->assertSame('value', $decode->data->key);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function setEncryptionMethod(): void
    {
        $this->rsa
            ->config(self::CONFIG_RSA)
            ->create();

        $encode = $this->jwt
            ->setEncryptionMethod($this->rsa)
            ->encode([
                'key' => 'value',
            ])
            ->get();

        $this->assertIsString($encode);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function get(): void
    {
        /** @var OpenSSLAsymmetricKey $privateKey */
        $privateKey = $this->rsa
            ->config(self::CONFIG_RSA)
            ->create()
            ->getPrivateKey();

        $jwt = $this->jwt
            ->config([
                'privateKey' => $privateKey,
            ])
            ->encode([
                'key' => 'value',
            ])
            ->get();

        $this->assertIsString($jwt);
    }
}
