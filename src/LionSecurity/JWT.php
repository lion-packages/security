<?php

namespace LionSecurity;

use \Closure;
use \DomainException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\Key;
use Firebase\JWT\JWT as FBJWT;
use \InvalidArgumentException;
use LionSecurity\RSA;
use \UnexpectedValueException;

class JWT {

	private static function execute(Closure $execute_function): object {
		try {
			return $execute_function();
		} catch (InvalidArgumentException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (DomainException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (SignatureInvalidException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (BeforeValidException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (ExpiredException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		} catch (UnexpectedValueException $e) {
			return (object) ['status' => "error", 'message' => $e->getMessage()];
		}
	}

	public static function encode(array $data, int $time = 0): object {
		RSA::init();

		return self::execute(function() use ($data, $time) {
			$now = strtotime("now");

			return (object) [
				'status' => "success",
				'message' => "JWT encodes correctly.",
				'data' => (object) [
					'jwt' => FBJWT::encode([
						'iss' => $_ENV['SERVER_URL'],
						'aud' => $_ENV['SERVER_URL_AUD'],
						"jti" => base64_encode(random_bytes(16)),
						"iat" => $now,
						"nbf" => $now,
						'exp' => $now + ($time === 0 ? ((int) $_ENV['JWT_EXP']) : $time),
						'data' => $data
					], RSA::getPrivateKey(), $_ENV['JWT_DEFAULT_MD'])
				]
			];
		});
	}

	public static function decode(?string $jwt): object {
		RSA::init();

		if ($jwt === 'null' || $jwt === null) {
			return (object) ['status' => "error", 'message' => "The JWT does not exist."];
		}

		return self::execute(function() use ($jwt) {
			return (object) [
				'status' => "success",
				'message' => "JWT decoded successfully.",
				'data' => (object) [
					'jwt' => FBJWT::decode(
						$jwt,
						new Key(RSA::getPublicKey(), $_ENV['JWT_DEFAULT_MD'])
					)
				]
			];
		});
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