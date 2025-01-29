<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\Exceptions\InvalidConfigException;
use Lion\Security\RSA;
use Lion\Test\Test;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\Test as Testing;
use ReflectionException;
use stdClass;

class RSATest extends Test
{
    private const string URL_PATH_EXAMPLE = './storage/example/';
    private const string URL_PATH_CUSTOM = './storage/custom-keys/';
    private const string URL_PATH = './storage/keys/';
    private const string RSA_CONFIG = '/etc/ssl/openssl.cnf';
    private const int RSA_PRIVATE_KEY_BITS = 2048;
    private const string RSA_DEFAULT_MD = 'sha256';
    private const array CONFIG = [
        'urlPath' => self::URL_PATH,
        'rsaConfig' => self::RSA_CONFIG,
        'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
        'rsaDefaultMd' => self::RSA_DEFAULT_MD,
    ];
    private const string KEY_NAME = 'user_name';
    private const string VALUE_NAME = 'Sleon';

    private RSA $rsa;

    /**
     * @throws ReflectionException
     */
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

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function config(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(self::CONFIG));
        $this->assertEquals(self::URL_PATH, $this->getPrivateProperty('urlPath'));
        $this->assertEquals(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
        $this->assertEquals(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingUrlPath(): void
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

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingRsaConfig(): void
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

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingRsaPrivateKeyBits(): void
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

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function configWithMissingRsaDefaultMd(): void
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

    #[Testing]
    public function create(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(self::CONFIG)->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    #[Testing]
    public function createWithCustomPath(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(['urlPath' => self::URL_PATH_CUSTOM])->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    #[Testing]
    public function createWithCustomRsaPrivateKeyBits(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->config(['rsaPrivateKeyBits' => 4096])->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    #[Testing]
    public function createWithCustomRsaDefaultMd(): void
    {

        $this->assertInstanceOf(RSA::class, $this->rsa->config(['rsaDefaultMd' => 'sha512'])->create());
        $this->assertFileExists("{$this->rsa->getUrlPath()}public.key");
        $this->assertFileExists("{$this->rsa->getUrlPath()}private.key");
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function encode(): void
    {
        $encode = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->encode(self::KEY_NAME, self::VALUE_NAME)
            ->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey(self::KEY_NAME, $encode);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function encodeToObject(): void
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

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function decode(): void
    {
        /** @var array<string, string> $encode */
        $encode = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->encode(self::KEY_NAME, self::VALUE_NAME)
            ->get();

        $decode = $this->rsa
            ->config(self::CONFIG)
            ->decode($encode)
            ->get();

        $this->assertIsArray($decode);
        $this->assertArrayHasKey(self::KEY_NAME, $decode);
        $this->assertSame(self::VALUE_NAME, $decode[self::KEY_NAME]);
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function decodeToObject(): void
    {
        /** @var array<string, string> $encode */
        $encode = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->encode(self::KEY_NAME, self::VALUE_NAME)
            ->get();

        $decode = $this->rsa
            ->config(self::CONFIG)
            ->decode($encode)
            ->toObject()
            ->get();

        $this->assertIsObject($decode);
        $this->assertObjectHasProperty(self::KEY_NAME, $decode);
        $this->assertSame(self::VALUE_NAME, $decode->user_name);
    }

    #[Testing]
    public function getPath(): void
    {
        $this->assertSame(self::URL_PATH, $this->rsa->config(['urlPath' => self::URL_PATH])->getUrlPath());
    }

    #[Testing]
    public function setUrlPath(): void
    {
        $this->assertInstanceOf(RSA::class, $this->rsa->setUrlPath(self::URL_PATH_EXAMPLE));
        $this->assertSame(self::URL_PATH_EXAMPLE, $this->rsa->getUrlPath());
    }

    #[Testing]
    public function getPublicKey(): void
    {
        $publicKey = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->getPublicKey();

        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $publicKey);
    }

    #[Testing]
    public function getPrivateKey(): void
    {
        $privateKey = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->getPrivateKey();

        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey);
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function rsaConfig(): void
    {
        $this->rsa->config(self::CONFIG);

        $this->assertSame(self::RSA_CONFIG, $this->getPrivateProperty('rsaConfig'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function rsaPrivateKeyBits(): void
    {
        $this->rsa->config(self::CONFIG);

        $this->assertSame(self::RSA_PRIVATE_KEY_BITS, $this->getPrivateProperty('rsaPrivateKeyBits'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function rsaDefaultMd(): void
    {
        $this->rsa->config(self::CONFIG);

        $this->assertSame(self::RSA_DEFAULT_MD, $this->getPrivateProperty('rsaDefaultMd'));
    }

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function toObject(): void
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

    /**
     * @throws InvalidConfigException
     */
    #[Testing]
    public function get(): void
    {
        $encode = $this->rsa
            ->config(self::CONFIG)
            ->create()
            ->encode(self::KEY_NAME, self::VALUE_NAME)
            ->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey(self::KEY_NAME, $encode);
    }
}
