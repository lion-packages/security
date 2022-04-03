<?php

namespace LionSecurity;

use Firebase\JWT\{ JWT as FJWT, Key };
use LionSecurity\RSA;

class JWT {

	public function __construct() {

	}

	public static function encode(array $data, int $time = 0): string {
		RSA::init();
		$now = strtotime("now");

		return FJWT::encode([
			'iss' => $_ENV['SERVER_URL'],
			'aud' => $_ENV['SERVER_URL_AUD'],
			"jti" => base64_encode(random_bytes(16)),
			"iat" => $now,
			"nbf" => $now,
			'exp' => $now + $_ENV['JWT_EXP'],
			'data' => $data
		], RSA::$private_key, $_ENV['JWT_DEFAULT_MD']);
	}

	public static function decode(string $jwt): object {
		RSA::init();

		return FJWT::decode(
			$jwt, new Key(RSA::$public_key, $_ENV['JWT_DEFAULT_MD'])
		);
	}

	public static function getToken(): string {
		$headers = apache_request_headers();

		if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
			return $matches[1];
		}
	}

}