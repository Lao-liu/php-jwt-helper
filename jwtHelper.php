<?php

class JWTHelper
{

	static function new($header, $payload, $secret) {
		$encodedHeader = self::_encodeArray($header);
		$encodedPayload = self::_encodeArray($payload);
		$signature = self::_generateSignature($encodedHeader, $encodedPayload,	$secret, $header['alg']);
		$jwt = "$encodedHeader.$encodedPayload.$signature";

		return $jwt;
	}

	protected static function _encodeArray($array) {
		$json = json_encode($array);
		$base64UrlEncoded = self::_base64UrlEncode($json);

		return $base64UrlEncoded;
	}

	protected static function _generateSignature($encodedHeader, $encodedPayload, $secret, $algorithm) {
		$algorithm = self::_determineAlgorithm($algorithm);
		$signature = hash_hmac($algorithm, "$encodedHeader.$encodedPayload", $secret, true);
		$encodedSignature = self::_base64UrlEncode($signature);

		return $encodedSignature;
	}

	protected static function _determineAlgorithm($algorithm) {
		$algorithm = strtolower($algorithm);
		switch ($algorithm) {
			case 'hs256':
				return 'sha256';
				break;
		}
	}

	protected static function _base64UrlEncode($input) {
		$base64Encoded = base64_encode($input);
		$base64UrlEncoded = preg_replace('/\+|\/|\=/', '', $base64Encoded);

		return $base64UrlEncoded;
	}

	static function parse($jwt) {
		$segments = self::split($jwt);
		$header = self::_decodeJwtSegment($segments[0]);
		$payload = self::_decodeJwtSegment($segments[1]);

		return ["header" => $header, "payload" => $payload];
	}

	protected static function _decodeJwtSegment($input) {
		$json = self::_base64UrlDecode($input);
		$array = json_decode($json, true);

		return $array;
	}

	protected static function _base64UrlDecode($input) {
		$decoded = base64_decode($input);

		return $decoded;
	}

	static function validate($jwt, $secret) {
		$segments = self::split($jwt);
		$algorithm = self::_extractAlgorithm($segments[0]);

		if (count($segments) < 3 || !$algorithm) {
			return false;
		}

		$returnedSignature = $segments[2];
		$generatedSignature = self::_generateSignature($segments[0], $segments[1], $secret, $algorithm);
		$jwtValidity = $returnedSignature === $generatedSignature;

		return $jwtValidity;
	}

	protected static function _extractAlgorithm($header) {
		$algorithmKey = 'alg';
		$header = self::_decodeJwtSegment($header);
		$algorithm = isset($header[$algorithmKey]) ? $header[$algorithmKey] : null;

		return $algorithm;
	}

	static function split($jwt) {
		$segments = preg_split("/\./", $jwt);

		return $segments;
	}

}

