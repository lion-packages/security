<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\AES;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;
use Lion\Test\Test;
use ReflectionClass;
use stdClass;
use Tests\Providers\AESEncryptionMethodProvider;

class AESTest extends Test
{
    use AESEncryptionMethodProvider;

    private AES $aes;
    private ReflectionClass $reflectionClass;

    protected function setUp(): void
    {
        $this->aes = new AES();

        $this->initReflection($this->aes);
    }

    /**
     * @dataProvider AESEncryptionMethodProvider
     */
    public function testConfig(string $method): void
    {
        $config = $this->aes->create($method)->get();

        $this->assertInstances($this->aes->config($config), [
            AES::class,
            ConfigInterface::class,
            EncryptionInterface::class,
            ObjectInterface::class
        ]);

        $this->assertSame($config, $this->getPrivateProperty('config'));
    }

    public function testGet(): void
    {
        $config = $this->aes->create(AES::AES_256_CBC)->get();
        $encode = $this->aes->config($config)->encode('user_name', 'Sleon')->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('user_name', $encode);
    }

    /**
     * @dataProvider AESEncryptionMethodProvider
     */
    public function testEncode(string $method): void
    {
        $config = $this->aes->create($method)->get();

        $this->assertInstances($this->aes->config($config)->encode('user_name', 'Sleon'), [
            AES::class,
            ConfigInterface::class,
            EncryptionInterface::class,
            ObjectInterface::class
        ]);

        $values = $this->aes->get();

        $this->assertArrayHasKey('user_name', $values);
        $this->assertIsString($values['user_name']);
    }

    public function testDecode(): void
    {
        $config = $this->aes->create(AES::AES_256_CBC)->get();

        $key1 = 'key1';
        $value1 = 'encoded_value_1';

        $key2 = 'key2';
        $value2 = 'encoded_value_2';

        $encode = $this->aes->config($config)->encode($key1, $value1)->encode($key2, $value2)->get();
        $decode = $this->aes->config($config)->decode($encode)->get();

        $this->assertArrayHasKey($key1, $decode);
        $this->assertArrayHasKey($key2, $decode);
        $this->assertSame($value1, $decode[$key1]);
        $this->assertSame($value2, $decode[$key2]);
    }

    public function testToObject(): void
    {
        $config = $this->aes->create(AES::AES_256_CBC)->get();
        $encode = $this->aes->config($config)->encode('user_name', 'Sleon')->toObject()->get();

        $this->assertInstanceOf(stdClass::class, $encode);
        $this->assertObjectHasProperty('user_name', $encode);
    }

    public function testClean(): void
    {
        $this->getPrivateMethod('clean');

        $this->assertSame([], $this->getPrivateProperty('values'));
        $this->assertSame([], $this->getPrivateProperty('config'));
    }

    /**
     * @dataProvider AESEncryptionMethodProvider
     * */
    public function testCipherKeyLength(string $method, int $bits): void
    {
        $lenght = $this->aes->cipherKeyLength($method);

        $this->assertIsInt($lenght);
        $this->assertSame($bits, $lenght);
    }

    public function testCipherKeyLengthNotExist(): void
    {
        $lenght = $this->aes->cipherKeyLength(uniqid());

        $this->assertIsBool($lenght);
        $this->assertFalse($lenght);
    }

    /**
     * @dataProvider AESEncryptionMethodProvider
     */
    public function testCreate(string $method, int $bits): void
    {
        $config = $this->aes->create($method)->get();

        $this->assertArrayHasKey('key', $config);
        $this->assertArrayHasKey('iv', $config);
        $this->assertArrayHasKey('method', $config);
        $this->assertSame($method, $config['method']);
    }
}
