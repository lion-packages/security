<?php

namespace LionSecurity;

use Firebase\JWT\{ SignatureInvalidException, BeforeValidException, ExpiredException };
use Firebase\JWT\{ Key, JWT as FBJWT };
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
			'exp' => $now + ($time === 0 ? ((int) $_ENV['JWT_EXP']) : $time),
			'data' => $data
		], RSA::$private_key, $_ENV['JWT_DEFAULT_MD']);
	}

	public static function decode(?string $jwt): object {
		RSA::init();

		if ($jwt === 'null' || $jwt === null) {
			return (object) ['status' => "error", 'message' => "The JWT does not exist."];
		}

		try {
			$jwtDec = FBJWT::decode($jwt, new Key(RSA::$public_key, $_ENV['JWT_DEFAULT_MD']));

			return (object) [
				'status' => "success",
				'message' => "JWT decoded successfully.",
				'data' => $jwtDec->data
			];
		} catch (SignatureInvalidException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (BeforeValidException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (ExpiredException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (\Exception $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		}
	}

	public static function get(): string {
		$headers = apache_request_headers();

		if (isset($headers['Authorization'])) {
			if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
				return $matches[1];
			}
		}

		return false;
	}

}