<?php

declare(strict_types=1);

namespace Tests;

use GuzzleHttp\Client;
use Lion\Security\AES;
use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\JWT;
use Lion\Security\RSA;
use Lion\Test\Test;
use PHPUnit\Framework\Attributes\DataProvider;

class JWTTest extends Test
{
    const string JWT_SERVER_URL = 'http://localhost:8000';
    const string JWT_SERVER_URL_AUD = 'http://localhost:5173';
    const int JWT_EXP = 3600;
    const string JWT_DEFAULT_MD = 'RS256';
    const array CONFIG_JWT_RSA = [
        'jwtServerUrl' => self::JWT_SERVER_URL,
        'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
        'jwtExp' => self::JWT_EXP,
        'jwtDefaultMD' => self::JWT_DEFAULT_MD
    ];
    const array CONFIG_JWT_AES = [
        'jwtServerUrl' => self::JWT_SERVER_URL,
        'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
        'jwtExp' => self::JWT_EXP,
        'jwtDefaultMD' => 'HS256'
    ];
    const string URL_PATH = './storage/keys/';
    const string RSA_CONFIG = '/etc/ssl/openssl.cnf';
    const int RSA_PRIVATE_KEY_BITS = 2048;
    const string RSA_DEFAULT_MD = 'sha256';
    const array CONFIG_RSA = [
        'urlPath' => self::URL_PATH,
        'rsaConfig' => self::RSA_CONFIG,
        'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
        'rsaDefaultMd' => self::RSA_DEFAULT_MD
    ];
    const string KEY = '0123456789sleon4';
    const string IV = 'sleon40123456789';
    const array CONFIG_AES = [
        'key' => self::KEY,
        'iv' => self::IV,
        'method' => AES::AES_256_CBC
    ];

    private JWT $jwt;
    private RSA $rsa;

    protected function setUp(): void
    {
        $this->rsa = new RSA();

        $this->jwt = new JWT();

        $this->initReflection($this->jwt);

        $this->createDirectory(self::URL_PATH);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursively('./storage/');
    }

    public function testConfig(): void
    {
        $this->jwt->config(self::CONFIG_JWT_RSA);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testConfigWithMissingJwtServerUrl(): void
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

    public function testConfigWithMissingJwtServerUrlAud(): void
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

    public function testConfigWithMissingJwtExp(): void
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

    public function testConfigWithMissingJwtDefaultMD(): void
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

    public function testEncodeWithRSA()
    {
        $privateKey = $this->rsa->config(self::CONFIG_RSA)->create()->getPrivateKey();

        $encode = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($encode);
    }

    public function testEncodeWithAES()
    {
        $encode = $this->jwt
            ->config(['privateKey' => self::IV, ...self::CONFIG_JWT_AES])
            ->encode(['key' => 'value'], 3600, 16)
            ->get();

        $this->assertIsString($encode);
    }

    public function testEncodeWithMissingPrivateKey(): void
    {
        $this->expectException(InvalidConfigException::class);

        $this->jwt->config([])->encode(['key' => 'value'], 3600, 16)->get();
    }

    public function testDecodeWithRSAValidJWT(): void
    {
        $this->rsa->config(self::CONFIG_RSA)->create();

        $privateKey = $this->rsa->getPrivateKey();

        $jwt = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($jwt);

        $publicKey = $this->rsa->getPublicKey();

        $decode = $this->jwt->config(['publicKey' => $publicKey])->decode($jwt)->get();

        $this->assertIsObject($decode);
        $this->assertObjectHasProperty('data', $decode);
        $this->assertObjectHasProperty('key', $decode->data);
        $this->assertSame('value', $decode->data->key);
    }

    public function testDecodeWithMissingPublicKey(): void
    {
        $this->expectException(InvalidConfigException::class);

        $this->jwt->config([])->decode(null)->get();
    }

    #[DataProvider('nullJwtDataProvider')]
    public function testDecodeWithNullJwt(?string $value): void
    {
        $publicKey = $this->rsa->config(self::CONFIG_RSA)->create()->getPublicKey();

        $decode = $this->jwt->config(['publicKey' => $publicKey])->decode($value)->get();

        $this->assertIsObject($decode);
        $this->assertObjectHasProperty('status', $decode);
        $this->assertObjectHasProperty('message', $decode);
        $this->assertSame('error', $decode->status);
        $this->assertSame('The JWT does not exist', $decode->message);
    }

    public static function nullJwtDataProvider(): array
    {
        return [[null], ['null'], ['']];
    }

    public function testJwtServerUrl(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
    }

    public function testJwtServerUrlAud(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
    }

    public function testJwtExp(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
    }

    public function testJwtDefaultMD(): void
    {
        $this->rsa->config(self::CONFIG_RSA);

        $this->assertSame(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testGetJWTWithValidAuthorizationHeader(): void
    {
        $this->rsa->config(self::CONFIG_RSA)->create();

        $jwt = $this->jwt
            ->config([
                'privateKey' => $this->rsa->getPrivateKey(),
            ])
            ->encode(['key' => 'value'], 3600, 16)
            ->get();

        $this->assertIsString($jwt);

        $getJwt = json_decode(
            (new Client())
                ->get(self::JWT_SERVER_URL, [
                    'headers' => [
                        'Authorization' => "Bearer {$jwt}"
                    ]
                ])
                ->getBody()
                ->getContents()
        );

        $this->assertSame($jwt, $getJwt);

        $decode = $this->jwt->config(['publicKey' => $this->rsa->getPublicKey()])->decode($getJwt)->get();

        $this->assertIsObject($decode);
        $this->assertObjectHasProperty('data', $decode);
        $this->assertObjectHasProperty('key', $decode->data);
        $this->assertSame('value', $decode->data->key);
    }

    public function testSetEncryptionMethod(): void
    {
        $this->rsa->config(self::CONFIG_RSA)->create();

        $encode = $this->jwt->setEncryptionMethod($this->rsa)->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($encode);
    }

    public function testGet(): void
    {
        $privateKey = $this->rsa->config(self::CONFIG_RSA)->create()->getPrivateKey();

        $jwt = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($jwt);
    }
}
