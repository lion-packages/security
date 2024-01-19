<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\Validation;
use LionTest\Test;

class ValidationTest extends Test
{
    private Validation $validation;

    protected function setUp(): void
    {
        $this->validation = new Validation();
    }

    public function testPasswordHash(): void
    {
        $hashedPassword = $this->validation->passwordHash('my_password');

        $this->assertIsString($hashedPassword);
        $this->assertNotEmpty($hashedPassword);
    }

    public function testValidateSuccess(): void
    {
        $result = $this->validation->validate(['field' => 'value'], function ($validator) {
            $validator->rule('required', 'field');
        });

        $this->assertEquals('success', $result->status);
        $this->assertEquals('validations have been completed', $result->message);
    }

    public function testValidateError(): void
    {
        $result = $this->validation->validate([], function ($validator) {
            $validator->rule('required', 'field');
        });

        $this->assertEquals('error', $result->status);
        $this->assertIsArray($result->messages);
    }

    public function testSha256(): void
    {
        $hashedValue = $this->validation->sha256('my_value');

        $this->assertIsString($hashedValue);
        $this->assertNotEmpty($hashedValue);
    }
}
