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
use PHPUnit\Framework\Attributes\Test as Testing;
use ReflectionException;
use stdClass;

class AESTest extends Test
{
    private AES $aes;

    protected function setUp(): void
    {
        $this->aes = new AES();

        $this->initReflection($this->aes);
    }

    /**
     * @throws Exception If the algorithm is not supported.
     * @throws ReflectionException If the property does not exist in the reflected
     * class.
     */
    #[Testing]
    public function config(): void
    {
        /** @var array{ key: string, iv: string } $config */
        $config = $this->aes
            ->create()
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
     * @throws AESException This class represents custom exceptions for AES class
     * processes.
     * @throws Exception If the algorithm is not supported.
     */
    #[Testing]
    public function get(): void
    {
        /** @var array{ key: string, iv: string } $config */
        $config = $this->aes
            ->create()
            ->get();

        $encode = $this->aes
            ->config([
                'key' => $config['key'],
            ])
            ->encode([
                'user_name' => 'Sleon4',
            ])
            ->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('data', $encode);
        $this->assertArrayHasKey('iv', $encode);
        $this->assertArrayHasKey('tag', $encode);
        $this->assertNotEmpty($encode['data']);
        $this->assertNotEmpty($encode['iv']);
        $this->assertNotEmpty($encode['tag']);
    }

    /**
     * @throws AESException This class represents custom exceptions for AES class
     * processes.
     * @throws Exception If the algorithm is not supported.
     */
    #[Testing]
    public function encode(): void
    {
        /** @var array{ key: string, iv: string } $config */
        $config = $this->aes
            ->create()
            ->get();

        $encode = $this->aes
            ->config([
                'key' => $config['key'],
            ])
            ->encode([
                'user_name' => 'Sleon4',
            ]);

        $this->assertInstances($encode, [
            AES::class,
            ConfigInterface::class,
            EncryptionInterface::class,
            ObjectInterface::class
        ]);

        $encode = $this->aes->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('data', $encode);
        $this->assertArrayHasKey('iv', $encode);
        $this->assertArrayHasKey('tag', $encode);
        $this->assertNotEmpty($encode['data']);
        $this->assertNotEmpty($encode['iv']);
        $this->assertNotEmpty($encode['tag']);
    }

    /**
     * @throws AESException
     * @throws Exception
     */
    #[Testing]
    public function decode(): void
    {
        /** @var array{ key: string, iv: string } $config */
        $config = $this->aes
            ->create()
            ->get();

        $encode = $this->aes
            ->config([
                'key' => $config['key'],
            ])
            ->encode([
                'user_name' => 'Sleon4',
            ])
            ->get();

        $this->assertIsArray($encode);
        $this->assertArrayHasKey('data', $encode);
        $this->assertArrayHasKey('iv', $encode);
        $this->assertArrayHasKey('tag', $encode);
        $this->assertNotEmpty($encode['data']);
        $this->assertNotEmpty($encode['iv']);
        $this->assertNotEmpty($encode['tag']);

        $decode = $this->aes
            ->config([
                'key' => $config['key'],
            ])
            ->decode($encode)
            ->get();

        $this->assertIsArray($decode);
        $this->assertNotEmpty($decode);
        $this->assertArrayHasKey('user_name', $decode);
        $this->assertSame('Sleon4', $decode['user_name']);
    }

    /**
     * @throws AESException
     * @throws Exception
     */
    #[Testing]
    public function toObject(): void
    {
        /** @var array{ key: string, iv: string } $config */
        $config = $this->aes
            ->create()
            ->get();

        $encode = $this->aes
            ->config([
                'key' => $config['key'],
            ])
            ->encode([
                'user_name' => 'Sleon4',
            ])
            ->toObject()
            ->get();

        $this->assertIsObject($encode);
        $this->assertInstanceOf(stdClass::class, $encode);
        $this->assertObjectHasProperty('data', $encode);
        $this->assertObjectHasProperty('iv', $encode);
        $this->assertObjectHasProperty('tag', $encode);
        $this->assertNotEmpty($encode->{'data'});
        $this->assertNotEmpty($encode->{'iv'});
        $this->assertNotEmpty($encode->{'tag'});
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
     * @throws Exception
     */
    #[Testing]
    public function create(): void
    {
        $config = $this->aes
            ->create()
            ->get();

        $this->assertIsArray($config);
        $this->assertNotEmpty($config);
        $this->assertArrayHasKey('key', $config);
        $this->assertArrayHasKey('iv', $config);
    }
}
