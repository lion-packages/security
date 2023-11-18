<?php

declare(strict_types=1);

namespace Tests;

use LionSecurity\AES;
use LionSecurity\Exceptions\InvalidConfigException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use stdClass;
use Tests\Support\Providers\AESEncryptionMethodProvider;

class AESTest extends TestCase
{
    use AESEncryptionMethodProvider;

    const KEY = '0123456789sleon4';
    const IV = 'sleon40123456789';
    const CONFIG = ['key' => self::KEY, 'iv' => self::IV, 'method' => AES::AES_256_CBC];

    private AES $aes;
    private ReflectionClass $reflectionClass;

    protected function setUp(): void
    {
        $this->aes = new AES();
        $this->reflectionClass = new ReflectionClass($this->aes);
    }

    public function testCipherKeyLength(): void
    {
        $lenght = $this->aes->cipherKeyLength(AES::AES_256_CBC);

        $this->assertIsInt($lenght);
        $this->assertSame(32, $lenght);
    }

    public function testCipherKeyLengthNotExist(): void
    {
        $lenght = $this->aes->cipherKeyLength(uniqid());

        $this->assertIsBool($lenght);
        $this->assertFalse($lenght);
    }

    public function testConfig(): void
    {
        $this->assertInstanceOf(AES::class, $this->aes->config(self::CONFIG));

        $keyProperty = $this->reflectionClass->getProperty('key');
        $keyProperty->setAccessible(true);

        $ivProperty = $this->reflectionClass->getProperty('iv');
        $ivProperty->setAccessible(true);

        $methodProperty = $this->reflectionClass->getProperty('method');
        $methodProperty->setAccessible(true);

        $this->assertSame(self::KEY, $keyProperty->getValue($this->aes));
        $this->assertSame(self::IV, $ivProperty->getValue($this->aes));
        $this->assertSame(AES::AES_256_CBC, $methodProperty->getValue($this->aes));
    }

    public function testConfigWithMissingKey(): void
    {
        $this->expectException(InvalidConfigException::class);

        $this->aes->config(['iv' => self::IV, 'method' => AES::AES_256_CBC]);
    }

    public function testConfigWithMissingIv(): void
    {
        $this->expectException(InvalidConfigException::class);

        $this->aes->config(['key' => self::KEY, 'method' => AES::AES_256_CBC]);
    }

    public function testConfigWithEmptyMethod(): void
    {
        $this->aes->config(['key' => self::KEY, 'iv' => self::IV, 'method' => '']);
        $methodProperty = $this->reflectionClass->getProperty('method');
        $methodProperty->setAccessible(true);

        $this->assertSame(AES::AES_256_CBC, $methodProperty->getValue($this->aes));
    }

    /**
     * @dataProvider AESEncryptionMethodProvider
     */
    public function testCreate(string $method, int $bits): void
    {
        $values = $this->aes->create($method)->get();

        $this->assertArrayHasKey('key', $values);
        $this->assertArrayHasKey('iv', $values);
        $this->assertArrayHasKey('bits', $values);
        $this->assertSame($bits, $values['bits']);
    }

    public function testMethod(): void
    {
        $methodProperty = $this->reflectionClass->getProperty('method');
        $methodProperty->setAccessible(true);

        $this->assertInstanceOf(AES::class, $this->aes->method(AES::AES_256_CBC));
        $this->assertSame(AES::AES_256_CBC, $methodProperty->getValue($this->aes));
    }

    public function testKey(): void
    {
        $keyProperty = $this->reflectionClass->getProperty('key');
        $keyProperty->setAccessible(true);

        $this->assertInstanceOf(AES::class, $this->aes->key(self::KEY));
        $this->assertSame(self::KEY, $keyProperty->getValue($this->aes));
    }

    public function testIv(): void
    {
        $keyProperty = $this->reflectionClass->getProperty('iv');
        $keyProperty->setAccessible(true);

        $this->assertInstanceOf(AES::class, $this->aes->iv(self::IV));
        $this->assertSame(self::IV, $keyProperty->getValue($this->aes));
    }

    public function testEncode(): void
    {
        $this->aes->config(self::CONFIG);
        $valuesProperty = $this->reflectionClass->getProperty('values');
        $valuesProperty->setAccessible(true);

        $this->assertInstanceOf(AES::class, $this->aes->encode('user_name', 'Sleon'));

        $values = $this->aes->get();

        $this->assertArrayHasKey('user_name', $values);
        $this->assertIsString($values['user_name']);
    }

    public function testDecode()
    {
        $key1 = 'key1';
        $key2 = 'key2';
        $value1 = 'encoded_value_1';
        $value2 = 'encoded_value_2';

        $encode = $this->aes->config(self::CONFIG)->encode($key1, $value1)->encode($key2, $value2)->get();
        $decode = $this->aes->config(self::CONFIG)->decode($encode)->get();

        $this->assertArrayHasKey($key1, $decode);
        $this->assertArrayHasKey($key2, $decode);
        $this->assertSame($value1, $decode[$key1]);
        $this->assertSame($value2, $decode[$key2]);
    }

    public function testToObject(): void
    {
        $encode = $this->aes->config(self::CONFIG)->encode('user_name', 'Sleon')->toObject()->get();

        $this->assertInstanceOf(stdClass::class, $encode);
        $this->assertObjectHasProperty('user_name', $encode);
    }

    public function testGet(): void
    {
        $encode = $this->aes->config(self::CONFIG)->encode('user_name', 'Sleon')->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('user_name', $encode);
    }
}
