<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\RSA;
use Lion\Test\Test;
use OpenSSLAsymmetricKey;
use stdClass;

class RSATest extends Test
{
    const URL_PATH_EXAMPLE = './storage/example/';
    const URL_PATH_CUSTOM = './storage/custom-keys/';
    const URL_PATH = './storage/keys/';
    const RSA_CONFIG = '/etc/ssl/openssl.cnf';
    const RSA_PRIVATE_KEY_BITS = 2048;
    const RSA_DEFAULT_MD = 'sha256';
    const CONFIG = [
        'urlPath' => self::URL_PATH,
        'rsaConfig' => self::RSA_CONFIG,
        'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
        'rsaDefaultMd' => self::RSA_DEFAULT_MD
    ];
    const KEY_NAME = 'user_name';
    const VALUE_NAME = 'Sleon';

    private RSA $rsa;

    protected function setUp(): void
    {
        $this->rsa = new RSA();

        $this->initReflection($this->rsa);
        $this->createDirectory(self::URL_PATH);
        $this->createDirectory(self::URL_PATH_CUSTOM);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursively('./storage/');
    }

    public function testConfig(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(self::CONFIG));
        $this->assertEquals(self::URL_PATH, $this->getPrivateProperty('urlPath'));
        $this->assertEquals(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
        $this->assertEquals(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    public function testConfigWithMissingUrlPath(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'rsaConfig' => self::RSA_CONFIG,
            'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
            'rsaDefaultMd' => self::RSA_DEFAULT_MD
        ]));

        $this->assertEquals(self::URL_PATH, $this->getPrivateProperty('urlPath'));
        $this->assertEquals(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
        $this->assertEquals(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    public function testConfigWithMissingRsaConfig(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'urlPath' => self::URL_PATH,
            'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
            'rsaDefaultMd' => self::RSA_DEFAULT_MD
        ]));

        $this->assertEquals(self::URL_PATH, $this->getPrivateProperty('urlPath'));
        $this->assertEquals(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
        $this->assertEquals(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    public function testConfigWithMissingRsaPrivateKeyBits(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'urlPath' => self::URL_PATH,
            'rsaConfig' => self::RSA_CONFIG,
            'rsaDefaultMd' => self::RSA_DEFAULT_MD
        ]));

        $this->assertEquals(self::URL_PATH, $this->getPrivateProperty('urlPath'));
        $this->assertEquals(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
        $this->assertEquals(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    public function testConfigWithMissingRsaDefaultMd(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'urlPath' => self::URL_PATH,
            'rsaConfig' => self::RSA_CONFIG,
            'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS
        ]));

        $this->assertEquals(self::URL_PATH, $this->getPrivateProperty('urlPath'));
        $this->assertEquals(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
        $this->assertEquals(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    public function testCreate(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(self::CONFIG)->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    public function testCreateWithCustomPath(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(['urlPath' => self::URL_PATH_CUSTOM])->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    public function testCreateWithCustomRsaPrivateKeyBits(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(['rsaPrivateKeyBits' => 4096])->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    public function testCreateWithCustomRsaDefaultMd(): void
    {

        $this->assertInstanceOf(RSA::class, $this->rsa->config(['rsaDefaultMd' => 'sha512'])->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    public function testEncode(): void
    {
        $encode = $this->rsa->config(self::CONFIG)->create()->encode(self::KEY_NAME, self::VALUE_NAME)->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey(self::KEY_NAME, $encode);
    }

    public function testEncodeToObject(): void
    {
        $encode = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->encode(self::KEY_NAME, self::VALUE_NAME)
            ->toObject()
            ->get();

        $this->assertIsObject($encode);
        $this->assertObjectHasProperty(self::KEY_NAME, $encode);
    }

    public function testDecode(): void
    {
        $encode = $this->rsa->config(self::CONFIG)->create()->encode(self::KEY_NAME, self::VALUE_NAME)->get();
        $decode = $this->rsa->config(self::CONFIG)->decode($encode)->get();

        $this->assertIsArray($decode);
        $this->assertArrayHasKey(self::KEY_NAME, $decode);
        $this->assertSame(self::VALUE_NAME, $decode[self::KEY_NAME]);
    }

    public function testDecodeToObject(): void
    {
        $encode = $this->rsa->config(self::CONFIG)->create()->encode(self::KEY_NAME, self::VALUE_NAME)->get();
        $decode = $this->rsa->config(self::CONFIG)->decode($encode)->toObject()->get();

        $this->assertIsObject($decode);
        $this->assertObjectHasProperty(self::KEY_NAME, $decode);
        $this->assertSame(self::VALUE_NAME, $decode->user_name);
    }

    public function testGetPath(): void
    {
        $this->assertSame(self::URL_PATH, $this->rsa->config(['urlPath' => self::URL_PATH])->getUrlPath());
    }

    public function testSetUrlPath(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->setUrlPath(self::URL_PATH_EXAMPLE));
        $this->assertSame(self::URL_PATH_EXAMPLE, $this->rsa->getUrlPath());
    }

    public function testGetPublicKey(): void
    {
        $publicKey = $this->rsa->config(self::CONFIG)->create()->getPublicKey();

        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $publicKey);
    }

    public function testGetPrivateKey(): void
    {
        $privateKey = $this->rsa->config(self::CONFIG)->create()->getPrivateKey();

        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey);
    }

    public function testRsaConfig(): void
    {
        $this->rsa->config(self::CONFIG);

        $this->assertSame(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
    }

    public function testRsaPrivateKeyBits(): void
    {
        $this->rsa->config(self::CONFIG);

        $this->assertSame(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
    }

    public function testRsaDefaultMd(): void
    {
        $this->rsa->config(self::CONFIG);

        $this->assertSame(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    public function testToObject(): void
    {
        $encode = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->encode(self::KEY_NAME, self::VALUE_NAME)
            ->toObject()
            ->get();

        $this->assertInstanceOf(stdClass::class, $encode);
        $this->assertObjectHasProperty(self::KEY_NAME, $encode);
    }

    public function testGet(): void
    {
        $encode = $this->rsa->config(self::CONFIG)->create()->encode(self::KEY_NAME, self::VALUE_NAME)->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey(self::KEY_NAME, $encode);
    }
}
