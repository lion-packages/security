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
     * @param array<string, mixed> $options [An associative array containing
     * options]
     *
     * @return string
     *
     * @infection-ignore-all
     */
    public function passwordHash(string $password, array $options = ['cost' => 12]): string
    {
        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    /**
     * Validate the data sent in an HTTP request with rules using Validator
     *
     * @param array<string, mixed>|Validator $data [List of data or Object to
     * validate]
     * @param Closure $validateFunction [Function that carries the rules logic
     * defined for validation]
     *
     * @return stdClass
     */
    public function validate(array|Validator $data, Closure $validateFunction): stdClass
    {
        $returnResponse = function (Validator $instance): stdClass {
            $validate = $instance->validate();

            if ($validate) {
                return (object) [
                    'code' => 200,
                    'status' => 'success',
                    'message' => 'validations have been completed',
                ];
            } else {
                return (object) [
                    'code' => 500,
                    'status' => 'error',
                    'messages' => $instance->errors(),
                ];
            }
        };

        if ($data instanceof Validator) {
            $validateFunction($data);

            return $returnResponse($data);
        }

        $validator = new Validator($data);

        $validateFunction($validator);

        return $returnResponse($validator);
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
