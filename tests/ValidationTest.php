<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\Validation;
use Lion\Test\Test;
use PHPUnit\Framework\Attributes\Test as Testing;
use PHPUnit\Framework\Attributes\TestWith;
use stdClass;
use Valitron\Validator;

class ValidationTest extends Test
{
    private Validation $validation;

    protected function setUp(): void
    {
        $this->validation = new Validation();
    }

    /**
     * @param array{
     *     cost: int
     * } $options
     *
     * @return void
     */
    #[Testing]
    #[TestWith(['options' => ['cost' => 14]])]
    #[TestWith(['options' => ['cost' => 13]])]
    #[TestWith(['options' => ['cost' => 12]])]
    #[TestWith(['options' => ['cost' => 11]])]
    #[TestWith(['options' => ['cost' => 10]])]
    #[TestWith(['options' => ['cost' => 9]])]
    #[TestWith(['options' => ['cost' => 8]])]
    #[TestWith(['options' => ['cost' => 7]])]
    #[TestWith(['options' => ['cost' => 6]])]
    #[TestWith(['options' => ['cost' => 5]])]
    #[TestWith(['options' => ['cost' => 4]])]
    public function passwordHash(array $options): void
    {
        $hashedPassword = $this->validation->passwordHash('my_password', $options);

        $this->assertNotEmpty($hashedPassword);
    }

    #[Testing]
    public function validateSuccess(): void
    {
        $response = $this->validation->validate(['field' => 'value'], function (Validator $validator): void {
            $validator->rule('required', 'field');
        });

        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(200, $response->code);
        $this->assertSame('success', $response->status);
        $this->assertSame('validations have been completed', $response->message);
    }

    #[Testing]
    public function validateError(): void
    {
        $response = $this->validation->validate([], function (Validator $validator) {
            $validator->rule('required', 'field');
        });

        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('messages', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsArray($response->messages);
        $this->assertSame(500, $response->code);
        $this->assertSame('error', $response->status);
        $this->assertIsArray($response->messages);
        $this->assertNotEmpty($response->messages);
        $this->assertArrayHasKey('field', $response->messages);
        $this->assertIsArray($response->messages['field']);
        $this->assertNotEmpty($response->messages['field']);
        $this->assertArrayHasKey(0, $response->messages['field']);

        $message = $response->messages['field'][0];

        $this->assertIsString($message);
        $this->assertSame('Field is required', $message);
    }

    #[Testing]
    public function sha256(): void
    {
        $hashedValue = $this->validation->sha256('my_value');

        $this->assertNotEmpty($hashedValue);
    }
}
