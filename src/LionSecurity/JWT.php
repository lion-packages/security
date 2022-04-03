<?php

namespace LionSecurity;

use Firebase\JWT\{ SignatureInvalidException, BeforeValidException, ExpiredException, Key, JWT as FBJWT };
use LionSecurity\RSA;

class JWT {

	public function __construct() {

	}

	public static function encode(array $data, int $time = 0): string {
		RSA::init();
		$now = strtotime("now");

		return FBJWT::encode([
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

		try {
			$jwt = FBJWT::decode(
				$jwt, new Key(RSA::$public_key, $_ENV['JWT_DEFAULT_MD'])
			);

			return (object) [
				'status' => "success",
				'message' => "JWT decoded successfully.",
				'data' => $jwt->data
			];
		} catch (SignatureInvalidException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (BeforeValidException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (ExpiredException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (Exception $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		}
	}

	public static function getToken(): string {
		$headers = apache_request_headers();

		if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
			return $matches[1];
		}
	}

}