<?php

namespace LionSecurity;

use Valitron\Validator;

class SECURITY {

	public function __construct() {

	}

	public static function passwordHash(string $file, array $config = []): string {
		$config = count($config) > 0 ? $config : [
			'cost' => 10
		];

		return password_hash($file, PASSWORD_BCRYPT, $config);
	}

	public static function validate(array $files, array $rules): object {
		$validator = new Validator($files);
		$validator->rules($rules);

		if ($validator->validate()) {
			return (object) [
				'status' => 'success',
				'message' => "",
				'data' => []
			];
		} else {
			return (object) [
				'status' => 'error',
				'message' => $validator->errors(),
				'data' => []
			];
		}
	}

	public static function sha256(string $value): string {
		return hash('sha256', $value);
	}

}