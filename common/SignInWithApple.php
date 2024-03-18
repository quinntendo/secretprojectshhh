<?php

require_once(LIB_DIR . '/FirebaseJWT/vendor/autoload.php');

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;

class IdTokenExpiredException extends Exception {
    
}

class SignInWithApple {

    static function validate($user, $password, $gameId) {

	$passwordJson = json_decode($password);
	//error_log("apple password " . $password);
	if (isset($passwordJson->id_token)) {

	    $gameSettings = getGameSettings($gameId);
	    $appId = $gameSettings['apple_app_id'];
	    $teamId = $gameSettings['apple_team_id'];
	    $keyId = $gameSettings['apple_key_id'];

	    $idToken = $passwordJson->id_token;
	    $validated = self::validateIdToken($user, $appId, $idToken);

	    //$authorizationCode = $passwordJson->authorization_code;
	    //error_log("validate apple " . $authorizationCode);
	    //self::validateAuthenticationCode($user, $gameId, $appId, $teamId, $keyId, $authorizationCode);

	    return $validated;
	}

	return false;
    }

    static function validateAuthenticationCode($user, $gameId, $appId, $teamId, $keyId, $authorizationCode) {

	$clientSecret = self::createClientSecret($appId, $teamId, $keyId); // cache this???
	//error_log("client_secret " . $client_secret);

	$response = postDataToUrl('https://appleid.apple.com/auth/token', [
	    'grant_type' => 'authorization_code',
	    'code' => $authorizationCode,
	    'client_id' => $appId,
	    'client_secret' => $clientSecret,
	]);

	if (!is_null($response)) {

	    //error_log("validate response " . $response);
	    $responseObj = json_decode($response);

	    if (isset($responseObj->error)) {
		error_log("Sign In With Apple error: " . $responseObj->error);
	    }

	    if (isset($responseObj->refresh_token)) {
		error_log("got refresh token");
		self::validateRefreshToken($user, $responseObj->refresh_token, $gameId);
		return true;
	    }

	    /* if(isset($responseObj->id_token)){

	      $id_token = $responseObj->id_token;

	      return self::validateIdToken($user, $appId, $id_token);
	      } */
	}
	return false;
    }

    static function validateIdToken($user, $appId, $idToken) {

	//throw new IdTokenExpiredException();
	//Verify the JWS E256 signature using the server’s public key
	$publicKey = self::getApplePublicKey();

	try {
	    $fullPublicKey = JWK::parseKeySet((array) $publicKey);
	    $decoded = JWT::decode($idToken, $fullPublicKey, array('RS256'));
	    //error_log("decoded " . print_r($decoded, true));
	} catch (ExpiredException $e) {
	    error_log("id token expired ");
	    throw new IdTokenExpiredException();
	    return false;
	} catch (Exception $e) {
	    error_log("id token invlaied " . $e->getMessage());
	    return false;
	}

	//Verify that the iss field contains https://appleid.apple.com
	if (!isset($decoded->iss) || $decoded->iss != "https://appleid.apple.com") {
	    error_log("validateIdToken bad iss");
	    return false;
	}

	//Verify that the time is earlier than the exp value of the token
	if (!isset($decoded->exp) || $decoded->exp < time()) {
	    error_log("validateIdToken is expired " . $decoded->exp . " < " . time());
	    return false;
	}

	//Verify that the aud field is the developer’s client_id
	if ($decoded->sub == $user && $decoded->aud == $appId) {
	    //error_log("validated IdToken");
	    return true;
	}

	return false;
    }

    static function validateRefreshToken($user, $refreshToken, $gameId) {

	//error_log("validate apple " . $refreshToken);

	$gameSettings = getGameSettings($gameId);
	$appId = $gameSettings['apple_app_id'];
	$teamId = $gameSettings['apple_team_id'];
	$keyId = $gameSettings['apple_key_id'];

	$clientSecret = self::createClientSecret($appId, $teamId, $keyId); // cache this???
	//error_log("client_secret " . $client_secret);

	$response = postDataToUrl('https://appleid.apple.com/auth/token', [
	    'grant_type' => 'refresh_token',
	    'refresh_token' => $refreshToken,
	    'client_id' => $appId,
	    'client_secret' => $clientSecret,
	]);

	if (!is_null($response)) {

	    error_log("validate refresh response " . $response);
	    $responseObj = json_decode($response);

	    if (isset($responseObj->error)) {
		error_log("Sign In With Apple error: " . $responseObj->error);
	    }

	    //access_token, token_type, expires_in
	    if (isset($responseObj->access_token)) {

		/* $access_token = $responseObj->access_token;

		  $claims = explode('.', $access_token)[1];
		  error_log("claims " . base64_decode($claims));
		  $claims = json_decode(base64_decode($claims));
		  $claims_user = $claims->sub;
		  $claims_appid = $claims->aud;

		  if(isset($claims->email)){
		  error_log("email " . $claims->email);
		  }

		  if($claims_user == $user && $claims_appid == $appId)
		  {
		  error_log("validated RefreshToken ");
		  //self::savedRefreshToken =
		  return true;
		  } */
	    }
	}
	return false;
    }

    static function createClientSecret($appId, $teamId, $keyId) {

	$time = time();

	$payload = array(
	    "iss" => $teamId,
	    "aud" => 'https://appleid.apple.com',
	    "iat" => $time,
	    "exp" => $time + 3600,
	    "sub" => $appId,
	);

	$key = 'file://sign_in_with_apple_keys/' . $keyId . '.p8';

	$jwt = JWT::encode($payload, $key, $alg = 'ES256', $keyId, $head = null);
	return $jwt;
    }

    static function getApplePublicKey() {

	$publicKey = CacheWrapper::get("siwa_apple_public_key");

	if (empty($publicKey) || $publicKey === false) {
	    error_log("get new siwa public key ");
	    $publicKey = getDataFromUrl("https://appleid.apple.com/auth/keys", false);
	    CacheWrapper::set("siwa_apple_public_key", $publicKey, CacheWrapper::TIMEOUT_TEN_MINUTES);
	}
	//error_log("public key " . $data);
	$responseObj = json_decode($publicKey, true);
	return $responseObj;
    }

}

?>