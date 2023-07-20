<?php

namespace LionSecurity;

use \OpenSSLAsymmetricKey;

class RSA {

	private static ?OpenSSLAsymmetricKey $public_key = null;
	private static ?OpenSSLAsymmetricKey $private_key = null;

	private static string $url_path = "storage/keys/";
	private static array $rsa_config = [
		'config' => '/etc/ssl/openssl.cnf',
		'private_key_bits' => 2048,
		'default_md' => 'sha256'
	];

	protected static function init(): void {
		if (self::$public_key === null) {
			self::$public_key = openssl_pkey_get_public(
				file_get_contents(self::$url_path . 'public.key')
			);
		}

		if (self::$private_key === null) {
			self::$private_key = openssl_pkey_get_private(
				file_get_contents(self::$url_path . 'private.key')
			);
		}
	}

	public static function createKeys(?string $url_path = null): void {
		$generate = openssl_pkey_new(self::$rsa_config);
		openssl_pkey_export($generate, $private, null, self::$rsa_config);
		$public = openssl_pkey_get_details($generate);

		$path_private_key = $url_path === null ? self::$url_path . 'private.key' : "{$url_path}private.key";
		$path_public_key = $url_path === null ? self::$url_path . 'public.key' : "{$url_path}public.key";
		file_put_contents($path_private_key, $private);
		file_put_contents($path_public_key, $public['key']);
	}

	public static function encode(array $rows): object {
		self::init();
		$data_list = [];

		foreach ($rows as $key => $row) {
			openssl_public_encrypt($row, $data, self::$public_key);
			$data_list[$key] = $data;
		}

		return (object) $data_list;
	}

	public static function decode(array $rows): object {
		self::init();
		$data_list = [];

		foreach ($rows as $key => $row) {
			openssl_private_decrypt($row, $data, self::$private_key);
			$data_list[$key] = $data;
		}

		return (object) $data_list;
	}

	public static function getConfig(): array {
		return self::$rsa_config;
	}

	public static function setConfig(array $rsa_config): void {
		self::$rsa_config = $rsa_config;
	}

	public static function getUrlPath(): string {
		return self::$url_path;
	}

	public static function setUrlPath(string $url_path): void {
		self::$url_path = $url_path;
	}

	public static function getPublicKey(): ?OpenSSLAsymmetricKey {
		return self::$public_key;
	}

	public static function getPrivateKey(): ?OpenSSLAsymmetricKey {
		return self::$private_key;
	}

}