<?php

declare(strict_types=1);

namespace Tests;

use Lion\Security\Validation;
use Lion\Test\Test;
use PHPUnit\Framework\Attributes\Test as Testing;
use Valitron\Validator;

class ValidationTest extends Test
{
    private Validation $validation;

    protected function setUp(): void
    {
        $this->validation = new Validation();
    }

    #[Testing]
    public function passwordHash(): void
    {
        $hashedPassword = $this->validation->passwordHash('my_password');

        $this->assertNotEmpty($hashedPassword);
    }

    #[Testing]
    public function validateSuccess(): void
    {
        $result = $this->validation->validate(['field' => 'value'], function (Validator $validator) {
            $validator->rule('required', 'field');
        });

        $this->assertEquals('success', $result->status);
        $this->assertEquals('validations have been completed', $result->message);
    }

    #[Testing]
    public function validateError(): void
    {
        $result = $this->validation->validate([], function (Validator $validator) {
            $validator->rule('required', 'field');
        });

        $this->assertEquals('error', $result->status);
        $this->assertIsArray($result->messages);
    }

    #[Testing]
    public function sha256(): void
    {
        $hashedValue = $this->validation->sha256('my_value');

        $this->assertNotEmpty($hashedValue);
    }
}
