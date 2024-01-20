<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\AES;
use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\JWT;
use Lion\Security\RSA;
use Lion\Test\Test;

class JWTTest extends Test
{
    const JWT_SERVER_URL = 'http://127.0.0.1:8000';
    const JWT_SERVER_URL_AUD = 'http://127.0.0.1:5173';
    const JWT_EXP = 3600;
    const JWT_DEFAULT_MD = 'RS256';
    const CONFIG_JWT_RSA = [
        'jwtServerUrl' => self::JWT_SERVER_URL,
        'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
        'jwtExp' => self::JWT_EXP,
        'jwtDefaultMD' => self::JWT_DEFAULT_MD
    ];
    const CONFIG_JWT_AES = [
        'jwtServerUrl' => self::JWT_SERVER_URL,
        'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
        'jwtExp' => self::JWT_EXP,
        'jwtDefaultMD' => 'HS256'
    ];
    const URL_PATH = './storage/keys/';
    const RSA_CONFIG = '/etc/ssl/openssl.cnf';
    const RSA_PRIVATE_KEY_BITS = 2048;
    const RSA_DEFAULT_MD = 'sha256';
    const CONFIG_RSA = [
        'urlPath' => self::URL_PATH,
        'rsaConfig' => self::RSA_CONFIG,
        'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
        'rsaDefaultMd' => self::RSA_DEFAULT_MD
    ];
    const KEY = '0123456789sleon4';
    const IV = 'sleon40123456789';
    const CONFIG_AES = ['key' => self::KEY, 'iv' => self::IV, 'method' => AES::AES_256_CBC];

    private JWT $jwt;
    private AES $aes;
    private RSA $rsa;

    protected function setUp(): void
    {
        $this->rsa = new RSA();
        $this->aes = new AES();
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

        $this->assertEquals(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertEquals(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertEquals(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertEquals(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testConfigWithMissingJwtServerUrl(): void
    {
        $this->jwt->config([
            'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
            'jwtExp' => self::JWT_EXP,
            'jwtDefaultMD' => self::JWT_DEFAULT_MD
        ]);

        $this->assertEquals(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertEquals(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertEquals(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertEquals(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testConfigWithMissingJwtServerUrlAud(): void
    {
        $this->jwt->config([
            'jwtServerUrl' => self::JWT_SERVER_URL,
            'jwtExp' => self::JWT_EXP,
            'jwtDefaultMD' => self::JWT_DEFAULT_MD
        ]);

        $this->assertEquals(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertEquals(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertEquals(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertEquals(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testConfigWithMissingJwtExp(): void
    {
        $this->jwt->config([
            'jwtServerUrl' => self::JWT_SERVER_URL,
            'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
            'jwtDefaultMD' => self::JWT_DEFAULT_MD
        ]);

        $this->assertEquals(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertEquals(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertEquals(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertEquals(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testConfigWithMissingJwtDefaultMD(): void
    {
        $this->jwt->config([
            'jwtServerUrl' => self::JWT_SERVER_URL,
            'jwtServerUrlAud' => self::JWT_SERVER_URL_AUD,
            'jwtExp' => self::JWT_EXP
        ]);

        $this->assertEquals(self::JWT_SERVER_URL, $this->getPrivateProperty('jwtServerUrl'));
        $this->assertEquals(self::JWT_SERVER_URL_AUD, $this->getPrivateProperty('jwtServerUrlAud'));
        $this->assertEquals(self::JWT_EXP, $this->getPrivateProperty('jwtExp'));
        $this->assertEquals(self::JWT_DEFAULT_MD, $this->getPrivateProperty('jwtDefaultMD'));
    }

    public function testEncodeWithValidConfig()
    {
        $privateKey = $this->rsa->config(self::CONFIG_RSA)->create()->getPrivateKey();
        $encode = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($encode);
    }

    public function testEncodeWithValidConfigWithAes()
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

    public function testDecodeWithValidJWT(): void
    {
        $this->rsa->config(self::CONFIG_RSA)->create();
        $privateKey = $this->rsa->getPrivateKey();
        $publicKey = $this->rsa->getPublicKey();
        $jwt = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($jwt);

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

    /**
     * @dataProvider nullJwtDataProvider
     * */
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
        $publicKey = $this->rsa->getPublicKey();
        $privateKey = $this->rsa->getPrivateKey();
        $jwt = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($jwt);

        $_SERVER['Authorization'] = "Bearer {$jwt}";

        $this->assertEquals($jwt, $this->jwt->getJWT());

        $decode = $this->jwt->config(['publicKey' => $publicKey])->decode($jwt)->get();

        $this->assertIsObject($decode);
        $this->assertObjectHasProperty('data', $decode);
        $this->assertObjectHasProperty('key', $decode->data);
        $this->assertSame('value', $decode->data->key);
    }

    public function testGet(): void
    {
        $privateKey = $this->rsa->config(self::CONFIG_RSA)->create()->getPrivateKey();
        $jwt = $this->jwt->config(['privateKey' => $privateKey])->encode(['key' => 'value'], 3600, 16)->get();

        $this->assertIsString($jwt);
    }
}
