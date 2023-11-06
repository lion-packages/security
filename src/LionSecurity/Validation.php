<?php

declare(strict_types=1);

namespace LionSecurity;

use Closure;
use Valitron\Validator;

class Validation
{
	public function passwordHash(string $file, array $config = []): string
    {
		$config = count($config) > 0 ? $config : ['cost' => 10];

		return password_hash($file, PASSWORD_BCRYPT, $config);
	}

	public function validate(array $files, Closure $validateFunction): object
    {
		$validator = new Validator($files);
		$validateFunction($validator);

		if ($validator->validate()) {
			return (object) ['status' => 'success', 'message' => "validations have been completed"];
		} else {
			return (object) ['status' => 'error', 'messages' => $validator->errors()];
		}
	}

	public function sha256(string $value): string
    {
		return hash('sha256', $value);
	}
}
