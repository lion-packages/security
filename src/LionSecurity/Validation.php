<?php

declare(strict_types=1);

namespace Lion\Security;

use Closure;
use stdClass;
use Valitron\Validator;

/**
 * Allows you to validate form data and generate encryption safely
 *
 * @package Lion\Security
 */
class Validation
{
    /**
     * Creates a password hash
     *
     * @param string $password [The user's password]
     * @param array<string, mixed> $options [An associative array containing options]
     *
     * @return string
     */
    public function passwordHash(string $password, array $options = ['cost' => 10]): string
    {
        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    /**
     * Validate the data sent in an HTTP request with rules using Validator
     *
     * @param array<string, mixed> $rows [Rows with data to validate]
     * @param Closure $validateFunction [Function that carries the rules logic
     * defined for validation]
     *
     * @return stdClass
     */
    public function validate(array $rows, Closure $validateFunction): stdClass
    {
        $validator = new Validator($rows);

        $validateFunction($validator);

        if ($validator->validate()) {
            return (object) [
                'code' => 200,
                'status' => 'success',
                'message' => 'validations have been completed',
            ];
        } else {
            return (object) [
                'code' => 500,
                'status' => 'error',
                'messages' => $validator->errors(),
            ];
        }
    }

    /**
     * Generates a cipher with the sha256 algorithm, produces a 256-bit
     * (32-byte) hash digest
     *
     * @param string $value [Value to encrypt]
     *
     * @return string
     */
    public function sha256(string $value): string
    {
        return hash('sha256', $value);
    }
}
