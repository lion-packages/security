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

	public static function passwordVerify(string $password, string $confirm_password): bool {
		return password_verify($password, $confirm_password);
	}

	public static function validate(array $files, array $rules): bool {
		$validator = new Validator($files);
		$validator->rules($rules);
		return $validator->validate();
	}

	public static function sha256(object $files): object {
		$data_list = [];

		foreach ($files as $key => $file) {
			$data_list[$key] = hash('sha256', $file);
		}

		return (object) $data_list;
	}

}