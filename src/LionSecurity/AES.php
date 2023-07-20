<?php

namespace LionSecurity;

class AES {

	public static function encode(string $key, string $iv, array $files): object {
		$data_list = [];

		foreach ($files as $key => $file) {
			$data_list[$key] = base64_encode(
				openssl_encrypt($file, $_ENV['AES_METHOD'], md5($key), OPENSSL_RAW_DATA, $iv)
			);
		}

		return (object) $data_list;
	}

	public static function decode(string $key, string $iv, array $files): object {
		$data_list = [];

		foreach ($files as $key => $file) {
			$data_list[$key] = openssl_decrypt(
				base64_decode($file), $_ENV['AES_METHOD'], md5($key), OPENSSL_RAW_DATA, $iv
			);
		}

		return (object) $data_list;
	}

}