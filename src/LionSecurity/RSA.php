<?php

namespace LionSecurity;

use \OpenSSLAsymmetricKey;

class RSA {

	public static ?OpenSSLAsymmetricKey $public_key = null;
	public static ?OpenSSLAsymmetricKey $private_key = null;
	public static string $path = "resources/secret/";

	public function __construct() {

	}

	public static function init(): void {
		if (self::$public_key === null) {
			self::$public_key = openssl_pkey_get_public(
				file_get_contents(self::$path . 'public.key')
			);
		}

		if (self::$private_key === null) {
			self::$private_key = openssl_pkey_get_private(
				file_get_contents(self::$path . 'private.key')
			);
		}
	}

	public static function createKeys(?string $url_path = null): void {
		$options = [
			'config' => $_ENV['RSA_PATH'],
			'private_key_bits' => $_ENV['RSA_PRIVATE_KEY_BITS'],
			'default_md' => $_ENV['RSA_DEFAULT_MD']
		];

		$generate = openssl_pkey_new($options);
		openssl_pkey_export($generate, $private, null, $options);
		$public = openssl_pkey_get_details($generate);

		if ($url_path != null) {
			file_put_contents("{$url_path}private.key", $private);
			file_put_contents("{$url_path}public.key", $public['key']);
		} else {
			file_put_contents(self::$path . 'private.key', $private);
			file_put_contents(self::$path . 'public.key', $public['key']);
		}
	}

	public static function encode(object $files): object {
		self::init();
		$data_list = [];

		foreach ($files as $key => $file) {
			openssl_public_encrypt($file, $data, self::$public_key);
			$data_list[$key] = $data;
		}

		return (object) $data_list;
	}

	public static function decode(object $files): object {
		self::init();
		$data_list = [];

		foreach ($files as $key => $file) {
			openssl_private_decrypt($file, $data, self::$private_key);
			$data_list[$key] = $data;
		}

		return (object) $data_list;
	}

}