<?php
class Encryption {

    static function encrypt($message, $initialVector, $secretKey) {
	$encrypted = openssl_encrypt($message, 'AES-128-CFB8', $secretKey, OPENSSL_RAW_DATA, $initialVector);
	return base64_encode($encrypted);
    }

    static function decrypt($message, $initialVector, $secretKey) {
	return openssl_decrypt($message, 'AES-128-CFB8', $secretKey, 0, $initialVector);
    }



}