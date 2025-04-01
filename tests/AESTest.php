<?php

declare(strict_types=1);

namespace Tests;

use Exception;
use Lion\Security\AES;
use Lion\Security\Exceptions\AESException;
use Lion\Security\Interfaces\ConfigInterface;
use Lion\Security\Interfaces\EncryptionInterface;
use Lion\Security\Interfaces\ObjectInterface;
use Lion\Test\Test;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test as Testing;
use ReflectionException;
use stdClass;
use Tests\Providers\AESEncryptionMethodProvider;

class AESTest extends Test
{
    use AESEncryptionMethodProvider;

    private AES $aes;

    /**
     * @throws ReflectionException
     */
    protected function setUp(): void
    {
        $this->aes = new AES();

        $this->initReflection($this->aes);
    }

    /**
     * @throws ReflectionException
     * @throws Exception
     */
    #[Testing]
    #[DataProvider('AESEncryptionMethodProvider')]
    public function config(string $method, int $bits, string $returnKey): void
    {
        /** @var array{
         *     passphrase?: string,
         *     key?: string,
         *     iv?: string,
         *     method?: string
         *  } $config */
        $config = $this->aes
            ->create($method)
            ->get();

        $this->assertInstances($this->aes->config($config), [
            AES::class,
            ConfigInterface::class,
            EncryptionInterface::class,
            ObjectInterface::class,
        ]);

        $this->assertSame($config, $this->getPrivateProperty('config'));
    }

    /**
     * @throws AESException
     * @throws Exception
     */
    #[Testing]
    public function get(): void
    {
        /** @var array{
         *     passphrase?: string,
         *     key?: string,
         *     iv?: string,
         *     method?: string
         *  } $config */
        $config = $this->aes
            ->create(AES::AES_256_CBC)
            ->get();

        $encode = $this->aes
            ->config($config)
            ->encode('user_name', 'Sleon')
            ->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('user_name', $encode);
    }

    /**
     * @throws AESException
     * @throws Exception
     */
    #[Testing]
    #[DataProvider('AESEncryptionMethodProvider')]
    public function encode(string $method, int $bits, string $returnKey): void
    {
        /** @var array{
         *     passphrase?: string,
         *     key?: string,
         *     iv?: string,
         *     method?: string
         *  } $config */
        $config = $this->aes
            ->create($method)
            ->get();

        $encode = $this->aes
            ->config($config)
            ->encode('user_name', 'Sleon');

        $this->assertInstances($encode, [
            AES::class,
            ConfigInterface::class,
            EncryptionInterface::class,
            ObjectInterface::class
        ]);

        $encode = $this->aes->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('user_name', $encode);
    }

    /**
     * @throws AESException
     * @throws Exception
     */
    #[Testing]
    public function decode(): void
    {
        /** @var array{
         *     passphrase?: string,
         *     key?: string,
         *     iv?: string,
         *     method?: string
         *  } $config */
        $config = $this->aes
            ->create(AES::AES_256_CBC)
            ->get();

        $key1 = 'key1';

        $value1 = 'encoded_value_1';

        $key2 = 'key2';

        $value2 = 'encoded_value_2';

        $encode = $this->aes
            ->config($config)
            ->encode($key1, $value1)
            ->encode($key2, $value2)
            ->get();

        $this->assertIsArray($encode);

        $decode = $this->aes
            ->config($config)
            ->decode($encode)
            ->get();

        $this->assertIsArray($decode);
        $this->assertArrayHasKey($key1, $decode);
        $this->assertArrayHasKey($key2, $decode);
        $this->assertSame($value1, $decode[$key1]);
        $this->assertSame($value2, $decode[$key2]);
    }

    /**
     * @throws AESException
     * @throws Exception
     */
    #[Testing]
    public function toObject(): void
    {
        /** @var array{
         *     passphrase?: string,
         *     key?: string,
         *     iv?: string,
         *     method?: string
         *  } $config */
        $config = $this->aes
            ->create(AES::AES_256_CBC)
            ->get();

        $encode = $this->aes
            ->config($config)
            ->encode('user_name', 'Sleon')
            ->toObject()
            ->get();

        $this->assertIsObject($encode);
        $this->assertInstanceOf(stdClass::class, $encode);
        $this->assertObjectHasProperty('user_name', $encode);
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    public function clean(): void
    {
        $this->getPrivateMethod('clean');

        $this->assertSame([], $this->getPrivateProperty('values'));
        $this->assertSame([], $this->getPrivateProperty('config'));
    }

    /**
     * @throws ReflectionException
     */
    #[Testing]
    #[DataProvider('formatCipherKeyProvider')]
    public function formatCipherKey(string $method, string $returnKey): void
    {
        $format = $this->getPrivateMethod('formatCipherKey', [
            'key' => $method,
        ]);

        $this->assertSame($returnKey, $format);
    }

    /**
     * @throws Exception
     */
    #[Testing]
    #[DataProvider('AESEncryptionMethodProvider')]
    public function cipherKeyLength(string $method, int $bits, string $returnKey): void
    {
        $lenght = $this->aes->cipherKeyLength($method);

        $this->assertSame($bits, $lenght);
    }

    /**
     * @throws Exception
     */
    #[Testing]
    public function cipherKeyLengthNotExist(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionCode(500);
        $this->expectExceptionMessage("The algorithm is not supported");

        $this->aes->cipherKeyLength(uniqid());
    }

    /**
     * @throws Exception
     */
    #[Testing]
    #[DataProvider('AESEncryptionMethodProvider')]
    public function testCreate(string $method, int $bits, string $returnKey): void
    {
        $config = $this->aes
            ->create($method)
            ->get();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('passphrase', $config);
        $this->assertArrayHasKey('key', $config);
        $this->assertArrayHasKey('iv', $config);
        $this->assertArrayHasKey('method', $config);
        $this->assertSame($returnKey, $config['method']);
    }
}
