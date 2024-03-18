<?php

require_once(GOOGLE_DIR . '/src/Google/Client.php');
require_once(GOOGLE_DIR . '/vendor/autoload.php');

trait Authentication {

    function authenticate($username, $password, $loginType) {
	$sql = 'SELECT id, account_id, hash, verified, country, UNIX_TIMESTAMP(last_login) AS last_login, UNIX_TIMESTAMP(NOW()) AS x_last_login
		    FROM logins
		WHERE username=? AND login_type=?';
	$sqlArgs = array($username, $loginType);
	$result = DbAuth::getObject($sql, $sqlArgs);
	if (!$result) {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_USERNAME);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}

	$hashFromDB = $result['hash'];
	$accountId = $result['account_id'];

	if ($loginType == LOGIN_TYPE_FACEBOOK) {
	    $this->validateFacebookUser($username, $password);
	} elseif ($loginType == LOGIN_TYPE_GAME_CENTER) {

	    $this->validateGameCenterUser($username, $password);
	} elseif ($loginType == LOGIN_TYPE_GOOGLE_PLAY) {

	    $this->validateGooglePlayUser($username, $password);
	} elseif ($loginType == LOGIN_TYPE_AMAZON) {

	    $this->validateAmazonUser($username, $password);
	} elseif ($loginType == LOGIN_TYPE_APPLE) {
	    $this->validateAppleUser($username, $password);
	} elseif ($loginType == LOGIN_TYPE_STEAM) {
	    $this->validateSteamUser($username, $password);
	} else {
	    if (!password_verify($password, $hashFromDB)) {
		sendErrorMessage(ResponseCode::AUTH_ERROR_PASSWORD);
		if (method_exists($this, 'haltProperly'))
		    $this->haltProperly();
		die();
	    }
	}

	if ($result['verified'] != 1) {
	    if ($loginType == LOGIN_TYPE_EMAIL && isEmailBanned($username))
		sendErrorMessage(ResponseCode::ERROR_EMAIL_BOUNCE, ResponseCode::getMessage(ResponseCode::ERROR_EMAIL_BOUNCE));
	    else
		sendErrorMessage(ResponseCode::AUTH_ACCOUNT_UNVERIFIED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}
	return $accountId;
    }

    public function validateGameCenterUser($playerId, $password) {

	if (strpos($playerId, 'FAKE_GC_') !== false || $this->gameId == 1) {
	    return;
	}

	$passwordJson = json_decode($password);

	if (array_key_exists('version', $passwordJson))
	    $this->validateGameCenterUserVersion2($playerId, $passwordJson);
	else
	    $this->validateGameCenterUserVersion1($playerId, $passwordJson);
    }

    public function validateGameCenterUserVersion1($playerId, $passwordJson) {

	$signature = base64_decode(rawurldecode($passwordJson->sig));
	$salt = base64_decode(rawurldecode($passwordJson->salt));
	$timestamp = base64_decode($passwordJson->ts);
	$publicKeyUrl = rawurldecode($passwordJson->pkurl);
	$bundleId = $passwordJson->bid;

	$payload = $this->concatPayload($playerId, $bundleId, $timestamp, rawurldecode($salt));

	$this->validateGameCenter($playerId, $publicKeyUrl, $signature, $payload);
	//error_log("verified game center");
    }

    public function validateGameCenterUserVersion2($playerId, $passwordJson) {

	$signature = base64_decode($passwordJson->sig);
	$salt = base64_decode($passwordJson->salt);
	$timestamp = ($passwordJson->ts);
//error_log("\$passwordJson: ".print_r($passwordJson, true));	
//error_log("validateGameCenterUserVersion2 $timestamp");	
	$publicKeyUrl = ($passwordJson->pkurl);

	/* $signature = base64_decode("Utz9Apeh/SEGWLfEuUo6jVyCFMvRuRF2vV1YW80gj4+oqpjiypbA/A6wDyk2kaui6CHbNNJFVyuAVkA6vN2Rjry5YEi8FuknNASHHRyKwlccLATuit3+K1JErFxV07+WFTg3Fejz1FWc0GTlbDXzL4j0PtgWYpg5bUnBITlDP/2SBdpakmX7Ty21Zx7ITXX1bcZnwqzNDN9IcYao+a6pLEmGeibYn1KyAjNnfn8zmGQeeL/E5N2asFC3VgRbJNhs94KhFRFHD8eF5a3qJZ7/FocNbMLD3/eZPP/g+/vsOkTqfzDctP8DrfOBHTOfZ+c2VL6PAxYEXPPxTD6e4ZYDEA==");
	  $salt =  base64_decode("vShyhQ==");
	  $timestamp =  1490968176349;
	  $publicKeyUrl = "https://static.gc.apple.com/public-key/gc-prod-3.cer";
	 */

	$bundleId = $passwordJson->bid;

	$payload = $playerId . $bundleId . $this->toBigEndian($timestamp, $playerId, $passwordJson) . $salt;

	$this->validateGameCenter($playerId, $publicKeyUrl, $signature, $payload);
	//error_log("verified game center");
    }

    protected function toBigEndian($timestamp, $playerId, $passwordJson) {
	try{
	    if (PHP_INT_SIZE === 4) {
		$hex = '';
		do {
		    $last = bcmod($timestamp, 16);
		    $hex = dechex($last) . $hex;
		    $timestamp = bcdiv(bcsub($timestamp, $last), 16);
		} while ($timestamp > 0);
		return hex2bin(str_pad($hex, 16, '0', STR_PAD_LEFT));
	    }
	    $highMap = 0xffffffff00000000;
	    $lowMap = 0x00000000ffffffff;
	    if(!is_numeric($timestamp)){
		error_log("*******************************************************");
		error_log(" BIGENDIAN NON NUMERIC VALUE IS : ".$timestamp);
		error_log("*******************************************************");
	    }
	    $higher = ($timestamp & $highMap) >> 32;
	    $lower = $timestamp & $lowMap;
	    
	    return pack('N2', $higher, $lower);
	    
	}catch(Exception $e){
	    error_log(print_r($passwordJson, true));
	    error_log("playerId: ".print_r($playerId, true));	
	    error_log("signature " . $passwordJson->sig . " " );
	    error_log("salt " . $passwordJson->salt );
	    error_log("timestamp " . $passwordJson->ts );
	    error_log("publicKeyUrl " . $publicKeyUrl );
	}
    }

    public function validateGameCenter($playerId, $publicKeyUrl, $signature, $payload, $pass = 1) {
	if (empty($publicKeyUrl)) {
	    //error_log("*******************************************************");
	    //error_log("Empty public key URL for GC playerId: $playerId");
	    error_log("Forcing publicKeyUrl for GC playerId: $playerId");
	    $publicKeyUrl = 'https://static.gc.apple.com/public-key/gc-prod-5.cer';
	    //error_log("*******************************************************");
	    //}else{
	    //	error_log("Public key URL for GC playerId: $playerId is $publicKeyUrl");
	}
	$sKey = $this->getApplePublicKey($publicKeyUrl);

	$isError = false;
	try {
	    $iResult = openssl_verify($payload, $signature, $sKey, OPENSSL_ALGO_SHA256);
	} catch (Exception $e) {
	    error_log("*********************************************************");
	    error_log("ValidateGameCenterException using URL $publicKeyUrl");
	    error_log("PlayerId: $playerId");
	    error_log(print_r($e, true));
	    error_log("*********************************************************");
	}
	$errorMsg = openssl_error_string();
	if ($iResult == 0) {
	    error_log("Game Center signature incorrect " . $errorMsg);
	    $isError = true;
	} else if ($iResult == -1) {
	    error_log("Game Center verify error " . $errorMsg);
	    $isError = true;
	} else if ($iResult == 1) {
	    //signature is good
	}

	if ($isError) {
	    if ($pass > 1) {
		$sql = "INSERT INTO gamecenter_login_fails SET gamecenter_id=?, reason=?, failed_on=NOW()";
		$sqlArgs = array($playerId, $iResult . ' ' . $errorMsg);
		DbAuth::query($sql, $sqlArgs);
		//sendErrorMessage(ResponseCode::AUTH_ERROR_GAMECENTER_AUTH_FAILED);
		//die();
	    } else
		$this->validateGameCenter($playerId, $publicKeyUrl, $signature, $payload, ++$pass);
	}
    }

    function getApplePublicKey($publicKeyUrl) {

	$sPublicKey = CacheWrapper::get("apple_public_key");

	if (empty($sPublicKey) || $sPublicKey === false) {
	    //error_log("****************** APPLE PUBLIC KEY EXPIRED ******************");

	    $data = getDataFromUrl($publicKeyUrl, false);
	    $data = chunk_split(base64_encode($data), 64, "\n");

	    $sPublicKey = "-----BEGIN CERTIFICATE-----\n" . $data . "-----END CERTIFICATE-----\n";
	    $sKey = openssl_pkey_get_public($sPublicKey);
	    if ($sKey === False) {
		error_log("Failed to get public key for game center\n");
		return false;
	    } else {
		$pemFile = APPLE_PUBLIC_KEY_FILE;
		file_put_contents($pemFile, $sPublicKey);
	    }
	    CacheWrapper::set("apple_public_key", $sPublicKey, CacheWrapper::TIMEOUT_TEN_MINUTES);
	}

	return $sPublicKey;
    }

    public function validateGooglePlayUserNew($playerId, $password) {
	try {
	    //error_log("player id " . $playerId . " token " . $password);

	    $gameSettings = getGameSettings($this->gameId);

	    // Check cache for this user's data
	    $cacheKey = "gpg_" . $playerId;
	    $cachedGPG = CacheWrapper::get($cacheKey);
	    if ($cachedGPG != null) {
		if ($cachedGPG->password == $password) {
		    error_log("Matched last login");
		    return;
		}
	    }

	    $clientSecret = $gameSettings['gp_client_secret'];
	    $webAppClientId = $gameSettings['gp_web_app_client_id'];
	    $appId = $gameSettings['gp_app_id'];

	    $client = new Google_Client();
	    $client->setClientId($webAppClientId);
	    $client->setClientSecret($clientSecret);
	    //$client->addScope(Google_Service_Oauth2::USERINFO_PROFILE);
	    //$client->setRedirectUri('http://' . $_SERVER['HTTP_HOST'] . '/oauth2callback.php');
	    //$client->setRedirectUri('postmessage');

	    $access_token_array = $client->authenticate($password);

	    if (!is_null($access_token_array)) {
		//error_log("access_token_array not null");
		//error_log(print_r($access_token_array, TRUE));

		if (isset($access_token_array['error'])) {
		    error_log("Google Play Auth token error: " . $access_token_array['error'] . ' description ' . $access_token_array['error_description']);
		}

		/*
		if (isset($access_token_array['access_token'])) {
		    error_log("access_token " . $access_token_array['access_token']);
		}
		*/
		$tokenAuthURL = "https://www.googleapis.com/games/v1/applications/" . $appId . "/verify/";
		$headers = array();
		$headers[] = 'Authorization: OAuth ' . $access_token_array['access_token'];
		$data = getDataFromUrl($tokenAuthURL, false, $headers);
		$gpDataObj = json_decode($data);
		//error_log("data " . $data);
		//error_log("after decode json");

		$lastJsonError = json_last_error();
		if ($lastJsonError != JSON_ERROR_NONE) {
		    error_log("JSON decoding error on Google Play return data...");
		    //error_log($jsonErrorMessages[$lastJsonError]);
		    sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
		    if (method_exists($this, 'haltProperly'))
			$this->haltProperly("An error occured. Check the logs.");
		    die("An error occured. Check the logs.");
		}

		//error_log("after decode json error check");

		if (isset($gpDataObj->error)) {
		    error_log("Google Play Auth token is invalid " . $gpDataObj->error);
		    sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
		    if (method_exists($this, 'haltProperly'))
			$this->haltProperly();
		    die();
		}

		//error_log("after error");

		if (isset($gpDataObj->player_id))
		    //error_log("Google Play Auth player id " . $gpDataObj->player_id);

		//error_log("after player id");
		$authData = new stdClass();
		$authData->device_id = $this->device_id;
		$authData->advertiser_id = $this->advertiser_id;
		$authData->gpgObject = $gpDataObj;
		$authData->password = $password;

		CacheWrapper::set($cacheKey, $authData, CacheWrapper::TIMEOUT_SIXTY_MINUTES);
	    } else
		error_log("access_token is null");
	} catch (Exception $e) {
	    error_log("exception " . $e->getMessage());
	    sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}
    }

    public function validateGooglePlayUser($playerId, $password) {

	if ($this->gpg_version >= 2)
	    $this->validateGooglePlayUserNew($playerId, $password);
	//Google play needs to get prevalidated because of id change

	/* if(is_null($password))
	  error_log("Google Play Auth token is null");

	  global $jsonErrorMessages;

	  $tokenAuthURL = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$password";
	  error_log($tokenAuthURL);

	  try{
	  $data = getDataFromUrl($tokenAuthURL, false);

	  $gpDataObj = json_decode($data);

	  $lastJsonError = json_last_error();
	  if ($lastJsonError != JSON_ERROR_NONE) {
	  error_log("JSON decoding error on Google Play return data...");
	  error_log($jsonErrorMessages[$lastJsonError]);
	  sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
	  die("An error occured. Check the logs.");
	  }

	  $gameSettings = getGameSettings($this->gameId);

	  if(isset($gpDataObj->error) )
	  error_log("Google Play Auth token is invalid");

	  if(isset($gpDataObj->user_id) && $gpDataObj->user_id != $playerId)
	  error_log("Google Play Auth token user " . $gpDataObj->user_id . "!=" . $playerId);

	  if(isset($gpDataObj->audience) && $gpDataObj->audience != $gameSettings['gp_client_id'])
	  error_log("Google Play Auth token client is " . $gpDataObj->audience . "!=" . $gameSettings['gp_client_id']);

	  // verify the response is what we expected
	  if (isset($gpDataObj->error)
	  || !(isset($gpDataObj->user_id) && $gpDataObj->user_id == $playerId)
	  ||  !(isset($gpDataObj->audience) && $gpDataObj->audience == $gameSettings['gp_client_id'])) {
	  sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
	  die();
	  }
	  }catch(Exception $e){
	  error_log($e->getMessage());
	  } */
    }

    public function validateAmazonUser($playerId, $password) {

	//error_log("Amazon Auth token " . $password);

	if (empty($password))
	    error_log("Amazon Auth token is null");

	global $jsonErrorMessages;

	$encodedPassword = urlencode($password);
	$tokenAuthURL = "https://api.amazon.com/auth/O2/tokeninfo?access_token=$encodedPassword";
	$data = getDataFromUrl($tokenAuthURL, false);

	//error_log("Amazon data " . $data);

	$dataObj = json_decode($data);

	$lastJsonError = json_last_error();
	if ($lastJsonError != JSON_ERROR_NONE) {
	    error_log("JSON decoding error on Amazon return data...");
	    error_log($jsonErrorMessages[$lastJsonError]);
	    sendErrorMessage(ResponseCode::AUTH_ERROR_AMAZON_AUTH_FAILED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly("An error occured. Check the logs.");
	    die("An error occured. Check the logs.");
	}

	if (isset($dataObj->error)) {
	    error_log("Amazon Auth failed " . $dataObj->error_description);
	    sendErrorMessage(ResponseCode::AUTH_ERROR_AMAZON_AUTH_FAILED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}

	$gameSettings = getGameSettings($this->gameId);

	if (isset($dataObj->user_id) && $dataObj->user_id != $playerId)
	    error_log("Amazon Auth token user " . $dataObj->user_id . "!=" . $playerId);

	if (isset($dataObj->app_id) && $dataObj->app_id != $gameSettings['amazon_app_id'])
	    error_log("Amazon Auth token appid is " . $dataObj->app_id . "!=" . $gameSettings['amazon_app_id']);

	// verify the response is what we expected
	if (isset($dataObj->error) || !(isset($dataObj->user_id) && $dataObj->user_id == $playerId) || !(isset($dataObj->app_id) && $dataObj->app_id == $gameSettings['amazon_app_id'])) {
	    error_log("Amazon Auth failed ");
	    if (isset($dataObj->user_id))
		error_log("Amazon Auth token user " . $dataObj->user_id . "!=" . $playerId);
	    if (isset($dataObj->app_id))
		error_log("Amazon Auth token appid is " . $dataObj->app_id . "!=" . $gameSettings['amazon_app_id']);
	    sendErrorMessage(ResponseCode::AUTH_ERROR_AMAZON_AUTH_FAILED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}
    }

    function validateFacebookUser($fbUserId, $accessToken) {

	//return true; //TODO: remove this, pretend everything is ok for now for testing

	global $jsonErrorMessages;

	$gameSettings = getGameSettings($this->gameId);
	$appId = $gameSettings['fb_app_id'];

	// get user data from FB based on the password (which is the active access_token)
	include_once(INSTALL_DIR . "/fb_config/{$appId}.php");
	$rawFbData = getDataFromUrl("https://graph.facebook.com/me/?access_token=$accessToken", false);

	$fbDataObj = json_decode($rawFbData);
	$lastJsonError = json_last_error();
	if ($lastJsonError != JSON_ERROR_NONE) {
	    error_log("JSON decoding error on FB graph return data...");
	    error_log($jsonErrorMessages[$lastJsonError]);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly("An error occured. Check the logs.");
	    die("An error occured. Check the logs.");
	}

	// verify the response is what we expected
	if (isset($fbDataObj->error) || !(isset($fbDataObj->id) && $fbDataObj->id == $fbUserId)) {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_FACEBOOK_AUTH_FAILED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}
    }

    public function validateAppleUser($playerId, $password) {

	try {
	    $isValidated = SignInWithApple::validate($playerId, $password, $this->gameId);
	} catch (IdTokenExpiredException $e) {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_CREDENTIALS_EXPIRED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}

	if ($isValidated == false) {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_APPLE_AUTH_FAILED);
	    if (method_exists($this, 'haltProperly'))
		$this->haltProperly();
	    die();
	}
    }

    public function validateSteamUser($playerId, $password) {

		$gameSettings = getGameSettings($this->gameId);
		$appId = $gameSettings['steam_app_id'];
		$key = $gameSettings['steam_web_api_key'];

		$result = getDataFromUrl("https://api.steampowered.com/ISteamUserAuth/AuthenticateUserTicket/v1/?key=$key&appid=$appId&ticket=$password", false);

		//error_log("steam auth result " . $result);
		$jsonObj = json_decode($result);

		if (!isset($jsonObj->response->params->steamid) || $jsonObj->response->params->steamid != $playerId) {
			sendErrorMessage(ResponseCode::AUTH_ERROR_STEAM_AUTH_FAILED);
			if (method_exists($this, 'haltProperly'))
				$this->haltProperly();
			die();
		}
    }

    function concatPayload($playerId, $bundleId, $timestamp, $salt) {
	$bytes = array_merge(
		unpack('C*', $playerId),
		unpack('C*', $bundleId),
		unpack('C*', $timestamp),
		unpack('C*', $salt)
	);

	$payload = '';
	foreach ($bytes as $byte) {
	    $payload .= chr($byte);
	}
	return $payload;
    }

    function addAccount() {
	$iterationCount = 1;
	$found = true;
	while ($found) {
	    $accountId = generateRandomString(ACCOUNT_ID_LENGTH);
	    try {
		$sql = "INSERT INTO accounts SET account_id=?, date_created=NOW()";
		$sqlArgs = array($accountId);
		DbAuth::query($sql, $sqlArgs);
		$found = false;
	    } catch (Exception $e) {
		if (strpos($e->getMessage(), "Duplicate entry") !== false) {
		    $iterationCount++;
		    if ($iterationCount > MAX_RANDOM_ITERATION_COUNT) {
			throw new Expection("Max random code generation iteration count exceeded");
		    }
		    error_log($e->getMessage());
		} else {
		    throw $e;
		}
	    }
	}
	return $accountId;
    }

}
