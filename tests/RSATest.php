<?php

declare(strict_types=1);

namespace Tests;

use LionSecurity\RSA;
use LionSecurity\Traits\FilesTrait;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class RSATest extends TestCase
{
    use FilesTrait;

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

    private RSA $rsa;
    private ReflectionClass $reflectionClass;

    protected function setUp(): void
    {
        $this->rsa = new RSA();
        $this->reflectionClass = new ReflectionClass($this->rsa);

        $this->createDirectory('./storage/keys/');
        $this->createDirectory('./storage/custom-keys/');
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursively('./storage/');
    }

    public function testConfig(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $rsaConfigProperty = $this->reflectionClass->getProperty('rsaConfig');
        $rsaConfigProperty->setAccessible(true);

        $rsaPrivateKeyBitsProperty = $this->reflectionClass->getProperty('rsaPrivateKeyBits');
        $rsaPrivateKeyBitsProperty->setAccessible(true);

        $rsaDefaultMdProperty = $this->reflectionClass->getProperty('rsaDefaultMd');
        $rsaDefaultMdProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config(self::CONFIG));
        $this->assertEquals(self::URL_PATH, $urlPathProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_CONFIG, $rsaConfigProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $rsaPrivateKeyBitsProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_DEFAULT_MD, $rsaDefaultMdProperty->getValue($this->rsa));
    }

    public function testConfigWithMissingUrlPath(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $rsaConfigProperty = $this->reflectionClass->getProperty('rsaConfig');
        $rsaConfigProperty->setAccessible(true);

        $rsaPrivateKeyBitsProperty = $this->reflectionClass->getProperty('rsaPrivateKeyBits');
        $rsaPrivateKeyBitsProperty->setAccessible(true);

        $rsaDefaultMdProperty = $this->reflectionClass->getProperty('rsaDefaultMd');
        $rsaDefaultMdProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'rsaConfig' => self::RSA_CONFIG,
            'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
            'rsaDefaultMd' => self::RSA_DEFAULT_MD
        ]));

        $this->assertEquals(self::URL_PATH, $urlPathProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_CONFIG, $rsaConfigProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $rsaPrivateKeyBitsProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_DEFAULT_MD, $rsaDefaultMdProperty->getValue($this->rsa));
    }

    public function testConfigWithMissingRsaConfig(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $rsaConfigProperty = $this->reflectionClass->getProperty('rsaConfig');
        $rsaConfigProperty->setAccessible(true);

        $rsaPrivateKeyBitsProperty = $this->reflectionClass->getProperty('rsaPrivateKeyBits');
        $rsaPrivateKeyBitsProperty->setAccessible(true);

        $rsaDefaultMdProperty = $this->reflectionClass->getProperty('rsaDefaultMd');
        $rsaDefaultMdProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'urlPath' => self::URL_PATH,
            'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS,
            'rsaDefaultMd' => self::RSA_DEFAULT_MD
        ]));

        $this->assertEquals(self::URL_PATH, $urlPathProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_CONFIG, $rsaConfigProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $rsaPrivateKeyBitsProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_DEFAULT_MD, $rsaDefaultMdProperty->getValue($this->rsa));
    }

    public function testConfigWithMissingRsaPrivateKeyBits(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $rsaConfigProperty = $this->reflectionClass->getProperty('rsaConfig');
        $rsaConfigProperty->setAccessible(true);

        $rsaPrivateKeyBitsProperty = $this->reflectionClass->getProperty('rsaPrivateKeyBits');
        $rsaPrivateKeyBitsProperty->setAccessible(true);

        $rsaDefaultMdProperty = $this->reflectionClass->getProperty('rsaDefaultMd');
        $rsaDefaultMdProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'urlPath' => self::URL_PATH,
            'rsaConfig' => self::RSA_CONFIG,
            'rsaDefaultMd' => self::RSA_DEFAULT_MD
        ]));

        $this->assertEquals(self::URL_PATH, $urlPathProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_CONFIG, $rsaConfigProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $rsaPrivateKeyBitsProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_DEFAULT_MD, $rsaDefaultMdProperty->getValue($this->rsa));
    }

    public function testConfigWithMissingRsaDefaultMd(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $rsaConfigProperty = $this->reflectionClass->getProperty('rsaConfig');
        $rsaConfigProperty->setAccessible(true);

        $rsaPrivateKeyBitsProperty = $this->reflectionClass->getProperty('rsaPrivateKeyBits');
        $rsaPrivateKeyBitsProperty->setAccessible(true);

        $rsaDefaultMdProperty = $this->reflectionClass->getProperty('rsaDefaultMd');
        $rsaDefaultMdProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config([
            'urlPath' => self::URL_PATH,
            'rsaConfig' => self::RSA_CONFIG,
            'rsaPrivateKeyBits' => self::RSA_PRIVATE_KEY_BITS
        ]));

        $this->assertEquals(self::URL_PATH, $urlPathProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_CONFIG, $rsaConfigProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_PRIVATE_KEY_BITS, $rsaPrivateKeyBitsProperty->getValue($this->rsa));
        $this->assertEquals(self::RSA_DEFAULT_MD, $rsaDefaultMdProperty->getValue($this->rsa));
    }

    public function testCreateWithDefaultPath(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config(self::CONFIG)->create());
        $this->assertFileExists($urlPathProperty->getValue($this->rsa) . 'public.key');
        $this->assertFileExists($urlPathProperty->getValue($this->rsa) . 'private.key');
    }

    public function testCreateWithCustomPath(): void
    {
        $urlPathProperty = $this->reflectionClass->getProperty('urlPath');
        $urlPathProperty->setAccessible(true);

        $this->assertInstanceOf(RSA::class, $this->rsa->config(['urlPath' => './storage/custom-keys/'])->create());
        $this->assertFileExists($urlPathProperty->getValue($this->rsa) . 'public.key');
        $this->assertFileExists($urlPathProperty->getValue($this->rsa) . 'private.key');
    }
}
