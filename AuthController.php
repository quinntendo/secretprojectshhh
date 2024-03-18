<?php

class AuthController extends ControllerBase {

    use Authentication;

    const LOGINS = 'l';
    const BIND_LOGIN_TYPE = 'bt';
    const BIND_USERNAME = 'bu';
    const BIND_PASSWORD = 'bp';
    const FORCE_REFRESH_ACCESS_TOKEN = 'fr';
    const MSM_ANON_CONVERTED = 'msm_anon_converted';
    const UPDATE_DEVICE = 'update_device';
    const MAX_RANDOM_ITERATION_COUNT = 3;
    const GDPR_AUTH_VERSION = "2.1.0";
    const REFRESH_TOKEN = 'refresh_token';

    protected $language;
    protected $device_id; // raw_android_id / idfv
    protected $advertiser_id; // gaid / idfa
    protected $auth_version; // X.X.X
    protected $client_version; // X.X.X
    protected $device_model; // YYYYYYYYY
    protected $device_vendor; // WWWWWW
    protected $os_version; // A.B.C
    protected $platform; // android/amazon/ios
    protected $lang; // en/fr/de/es/it/pt/ru
    //use to identify devices banned from sending email
    protected $ban_device_id;

    public function init() {
	$this->gameId = $this->reqParam(parent::GAME_ID);

	$routePath = $this->app->router()->getCurrentRoute()->getPattern();

	$this->language = $this->hasParam('language') ? $this->reqParam('language') : 'en';

	//device info
	$this->device_id = $this->hasParam('device_id') ? $this->reqParam('device_id') : null; // raw_android_id / idfv
	$this->advertiser_id = $this->hasParam('advertiser_id') ? $this->reqParam('advertiser_id') : 'unknown'; // gaid / idfa
	$this->auth_version = $this->hasParam('auth_version') ? $this->reqParam('auth_version') : null; // X.X.X
	$this->client_version = $this->hasParam('client_version') ? $this->reqParam('client_version') : null; // X.X.X
	$this->device_model = $this->hasParam('device_model') ? $this->reqParam('device_model') : null; // YYYYYYYYY
	$this->device_vendor = $this->hasParam('device_vendor') ? $this->reqParam('device_vendor') : null; // WWWWWW
	$this->os_version = $this->hasParam('os_version') ? $this->reqParam('os_version') : null; // A.B.C
	$this->platform = $this->hasParam('platform') ? $this->reqParam('platform') : null; // android/amazon/ios
	$this->lang = $this->hasParam('lang') ? $this->reqParam('lang') : 'en'; // en/fr/de/es/it/pt/ru

	$this->gpg_version = $this->hasParam('gpg_version') ? $this->reqParam('gpg_version') : 1;

	$this->ban_device_id = $this->device_id;
    }

    public function preflight() {
	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Accept, Origin, Host, content-length, Connection, User-Agent, Referer, Accept-Encoding, Accept-Language");
	header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS");
    }

    private function updateDeviceInfo($userGameId) {

	if (is_null($this->device_id) || is_null($this->auth_version) || is_null($userGameId)) {
	    error_log("Cannot updateDeviceInfo: data is missing");
	    return false;
	}

	//error_log("updateDeviceInfo");

	$sql = 'INSERT INTO devices SET device_id=?, advertiser_id=?, platform=?, device_model=?, device_vendor=?, os_version=?, ip=?, date_installed=NOW()
				 ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), device_model=?, device_vendor=?, os_version=?, ip=?';
	$sqlArgs = array($this->device_id, $this->advertiser_id, $this->platform, $this->device_model, $this->device_vendor, $this->os_version, getRealIpAddr(),
	    $this->device_model, $this->device_vendor, $this->os_version, getRealIpAddr());
	DbAuth::query($sql, $sqlArgs);
	$device = DbAuth::getDb()->insert_id;

	$sql = 'INSERT INTO user_game_devices SET device_fk=?, user_game_id=?, auth_version=?, date_created=NOW(), last_played=NOW()
				ON DUPLICATE KEY UPDATE auth_version=?, last_played=NOW()';
	$sqlArgs = array($device, $userGameId, $this->auth_version, $this->auth_version);
	DbAuth::query($sql, $sqlArgs);

	return true;
    }

    public function googlePlayerIdChangeCheck($playerId, $password) {

	//error_log("player id " . $playerId . " token " . $password);

	if ($this->gpg_version >= 2)
	    return;

	if (is_null($password))
	    error_log("Google Play Auth token is null");

	global $jsonErrorMessages;

	$encodedPassword = urlencode($password);
	$tokenAuthURL = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$encodedPassword";
	//error_log($tokenAuthURL);

	try {
	    $data = getDataFromUrl($tokenAuthURL, false);

	    $gpDataObj = json_decode($data);

	    $lastJsonError = json_last_error();
	    if ($lastJsonError != JSON_ERROR_NONE) {
		error_log("JSON decoding error on Google Play return data...");
		error_log($jsonErrorMessages[$lastJsonError]);
		sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
		$this->haltProperly("An error occured. Check the logs.");
	    }

	    if (isset($gpDataObj->error))
		error_log("Google Play Auth token is invalid " . $gpDataObj->error . " playerId " . $playerId);

	    $validClientId = true;

	    $gameSettings = getGameSettings($this->gameId);

	    if (isset($gpDataObj->audience) && $gpDataObj->audience != $gameSettings['gp_client_id']) {
		error_log("Google Play Auth token client " . $gpDataObj->audience . "!=" . $gameSettings['gp_client_id']);
		$validClientId = false;
	    }

	    //error_log("user id " . $gpDataObj->user_id);

	    if ($validClientId) {

		$resultPlayerId = $this->getLoginData($playerId, LOGIN_TYPE_GOOGLE_PLAY);
		if (is_null($resultPlayerId) && isset($gpDataObj->user_id) && $gpDataObj->user_id != $playerId) {
		    error_log("Google Play Auth token user " . $gpDataObj->user_id . "!=" . $playerId);
		    //look for old player id found in token
		    $resultUserId = $this->getLoginData($gpDataObj->user_id, LOGIN_TYPE_GOOGLE_PLAY);

		    if (!is_null($resultUserId)) {
			//add new player id login, this must be the new id right?
			$this->addLogin($resultUserId['account_id'], $playerId, "", LOGIN_TYPE_GOOGLE_PLAY, true, false);
			error_log("Google Play Auth adding new login " . $playerId . " to " . $gpDataObj->user_id . " account");
		    }
		}
	    }

	    // verify the response is what we expected
	    if (isset($gpDataObj->error) || !$validClientId) {
		error_log("Google Play Auth token not valid ");
		sendErrorMessage(ResponseCode::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED);
		$this->haltProperly();
	    }

	    if ($gpDataObj->user_id != $playerId)
		return $gpDataObj->user_id;
	} catch (Exception $e) {
	    if (isSlimException($e))
		return;

	    error_log($e->getMessage());
	}
    }

    public function getLoginData($username, $loginType) {
	$sql = "SELECT * FROM logins WHERE username=? AND login_type=?";
	$sqlArgs = array($username, $loginType);
	$result = DbAuth::getObject($sql, $sqlArgs);
	return $result;
    }

    public function getGamesByAccountId($accountId, $gameId = null) {
	$sql = "SELECT * FROM user_games WHERE account_id=?";
	if (!is_null($gameId)) {
	    $sql .= " AND game=$gameId";
	}
	$sqlArgs = array($accountId);
	$result = DbAuth::getObjects($sql, $sqlArgs);
	return $result;
    }

    public function getUserGameId($accountId) {
	$sql = "SELECT user_game_id FROM user_games WHERE account_id=? AND game=?";
	$sqlArgs = array($accountId, $this->gameId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	return $result['user_game_id'];
    }

    public function getLoginsByAccountId($accountId) {
	$sql = "SELECT * FROM logins WHERE account_id=?";
	$sqlArgs = array($accountId);
	$result = DbAuth::getObjects($sql, $sqlArgs);
	return $result;
    }

    public function requestToken() {
	$username = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);
	$gameId = $this->reqParam(self::GAME_ID);

	if (!$this->hasParam(self::LOGIN_TYPE)) {
	    if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
		$loginType = 'email';
	    } else {
		sendErrorMessage(ResponseCode::AUTH_ERROR_INVALID_TYPE);
		$this->haltProperly();
	    }
	} else {
	    $loginType = $this->reqParam(self::LOGIN_TYPE);
	}

	//need to check if googleplay exists under different id before authenticate gets called
	if ($loginType == LOGIN_TYPE_GOOGLE_PLAY)
	    $this->googlePlayerIdChangeCheck($username, $password);

	$responseJson = $this->GetCachedAccessToken($gameId, $loginType, $username, $password);

	$forceRefresh = $this->hasParam(self::FORCE_REFRESH_ACCESS_TOKEN);

	if (!$forceRefresh && !empty($responseJson)) {
	    $response = json_decode($responseJson);
	    $this->addTokenToHeader($response->access_token);
	    echo $responseJson;
	} else {

	    //only send refresh tokens for apple logins with credentials
	    $sendRefreshToken = false;
	    if ($loginType == LOGIN_TYPE_APPLE) {
		$sendRefreshToken = true;
	    }

	    $accountId = $this->authenticate($username, $password, $loginType);

	    $this->handleTokenRequest($username, $password, $loginType, $accountId, $sendRefreshToken);
	}
    }

    public function GetCachedAccessToken($gameId, $loginType, $username, $password) {

	$trimmedCacheKey = $gameId . '-' . $loginType . '-' . trim($username) . '-' . $password;
	$cacheKey = md5($trimmedCacheKey);
	$accessToken = CacheWrapper::get($cacheKey);

	return $accessToken;
    }

    public function refreshToken() {

	$refreshToken = $this->reqParam(self::REFRESH_TOKEN);

	$gameSettings = getGameSettings($this->gameId);
	$decryptedToken = Encryption::decrypt($refreshToken, $gameSettings['refresh_token_encryption_vector'], $gameSettings['refresh_token_encryption_secret']);

	if (empty($decryptedToken)) {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_REFRESH_TOKEN_AUTH_FAILED);
	    $this->haltProperly();
	}

	$token = json_decode($decryptedToken);
	
	$refreshToken = $this->validateRefreshToken($token);
	if ($refreshToken) {

	    //check for cached access token
	    $responseJson = $this->GetCachedAccessToken($this->gameId, $refreshToken->login_type, $refreshToken->username, $refreshToken->guid);
	    $forceRefresh = $this->hasParam(self::FORCE_REFRESH_ACCESS_TOKEN);

	    if (!$forceRefresh && !empty($responseJson)) {
		$response = json_decode($responseJson);
		$this->addTokenToHeader($response->access_token);
		echo $responseJson;
	    } else {
		$this->handleTokenRequest($token->username, $token->guid, $token->login_type, $token->account_id, false);
	    }
	} else {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_REFRESH_TOKEN_AUTH_FAILED);
	    $this->haltProperly();
	}
    }

    function validateRefreshToken($refreshToken) {

	//error_log("validating with refresh token ");
	if (is_null($refreshToken)) {
	    return false;
	}

	if ($refreshToken->expires_at < time()) {
	    //error_log("expired token" );
	    return false;
	}

	$sql = "SELECT * FROM devices WHERE device_id=? AND advertiser_id=?";
	$args = array($this->device_id, $this->advertiser_id);
	$device = DbAuth::getObject($sql, $args);
	$deviceFk = is_null($device) ? NULL : $device['id'];

	$sql = "SELECT * FROM user_games WHERE user_game_id=? AND game=?";
	$args = array($refreshToken->user_game_ids[0], $this->gameId);
	$result = DbAuth::getObject($sql, $args);

	if(is_null($result)){
	    return false;
	}
	$userGamesFk = $result['id'];
	
	$sql = "SELECT * FROM refresh_tokens WHERE user_games_fk=? AND devices_fk=?";
	$args = array($userGamesFk, $deviceFk);
	$result = DbAuth::getObject($sql, $args);
	if (!is_null($result)) {
	    if ($refreshToken->guid != $result['refresh_token']) {
		//error_log("refresh token revoked" );
		return false;
	    }
	} else {
	    //error_log("no refresh token in db" );
	    return false;
	}

	//maybe remove this and have csr tool should invalidate token for efficiency
	$userGameIds = $this->getUserGameIdsForAccount($refreshToken->account_id, $this->gameId);
	if (!in_array($refreshToken->user_game_ids[0], $userGameIds, true)) {
	    //error_log("resfresh token usergameid swapped" );
	    return false;
	}

	return $refreshToken;
    }

    function handleTokenRequest($username, $password, $loginType, $accountId, $sendRefreshToken) {

	$this->checkGDPRConsent($accountId);

	if ($this->hasParam(self::MSM_ANON_CONVERTED))
	    $this->removeMsmAnon($username);

	$tokenJson = $this->getToken($accountId, $username, $loginType);

	$encryptedToken = $this->encryptToken($tokenJson);
	$this->addTokenToHeader($encryptedToken); //Remove after clients are updated
	$tokenObj = json_decode($tokenJson);

	$deviceInfoUpdated = false;
	foreach ($tokenObj->user_game_ids as $userGameId) {
	    if ($this->hasParam(self::UPDATE_DEVICE)) {
		$deviceInfoUpdated = $this->updateDeviceInfo($userGameId);
	    }

	    // update the IP address
	    // temp block to help clear out some of the null records in the data
	    $ipAddress = getRealIpAddr();
	    if (DbAuth::objectExists("SELECT * FROM user_ips WHERE user_game_id=? AND ip_address IS NULL", array($userGameId))) {
		if (DbAuth::objectExists("SELECT * FROM user_ips WHERE user_game_id=? AND ip_address=?", array($userGameId, $ipAddress))) {
		    $sql = "UPDATE user_ips SET event_date=NOW() WHERE user_game_id=? AND ip_address=?";
		    $sqlArgs = array($userGameId, $ipAddress);
		} else {
		    $sql = "UPDATE user_ips SET user_game_id=?, ip_address=?, event_date=NOW() WHERE user_game_id=? AND ip_address IS NULL";
		    $sqlArgs = array($userGameId, $ipAddress, $userGameId);
		}
	    } else {
		$sql = "INSERT INTO user_ips SET user_game_id=?, ip_address=?, event_date=NOW() ON DUPLICATE KEY UPDATE event_date=NOW()";
		$sqlArgs = array($userGameId, $ipAddress);
	    }
	    DbAuth::query($sql, $sqlArgs);
	}

	$response = new stdClass();
	$response->ok = true;
	$response->user_game_id = $tokenObj->user_game_ids;

	//add recoverable login types
	$sql = "SELECT DISTINCT login_type FROM logins WHERE account_id=? AND login_type != 'anon' AND login_type != 'msm_anon'";
	$sqlArgs = array($accountId);
	$result = DbAuth::getObjects($sql, $sqlArgs);

	$loginsString = '[';
	foreach ($result as $login) {
	    if (strlen($loginsString) > 1)
		$loginsString .= ',';
	    $loginsString .= $login['login_type'];
	}
	$loginsString .= ']';
	//print($loginsString);
	$response->login_types = $loginsString;
	$response->access_token = $encryptedToken;
	$response->token_type = "bearer";
	$response->expires_at = $tokenObj->expires_at;
	if (property_exists($tokenObj, 'permissions')){
	    
	    $response->permissions = $tokenObj->permissions;
	    //error_log(print_r($response->permissions, true));
	    // only do MFA for non is_server permissions
	    if (!property_exists($response->permissions, 'is_server'))
	    {
		$result = DbAuth::getObject("SELECT * FROM login_mfas WHERE account_id=?", array($accountId));
		$response->mfa_required = true;
		if($result){
		    $response->mfa_confirmed = (bool)$result['confirmed'];
		}
	    }	    
	}
	if ($deviceInfoUpdated)
	    $response->device_updated = true;

	if ($sendRefreshToken) {
	    //error_log("send refresh token");
	    $userGameIds = $this->getUserGameIdsForAccount($accountId, $this->gameId);
	    $encryptedRefreshToken = createRefreshToken($accountId, $userGameIds, $this->gameId, $username, $loginType, $this->device_id, $this->advertiser_id);
	    $response->refresh_token = $encryptedRefreshToken;
	}

	$responseJson = json_encode($response);

	$trimmedCacheKey = $this->gameId . '-' . $loginType . '-' . trim($username) . '-' . $password;
	$cacheKey = md5($trimmedCacheKey);

	$gameSettings = getGameSettings($this->gameId);
	
	// this will cache the cachekey so we can delete the cached stuff if the user decides to update their password while this token is still being cached
	//CacheWrapper::set($this->gameId . '-' . $loginType . '-' . trim($username).'_pass', $cacheKey, $gameSettings['token_expires_after'] - CacheWrapper::TIMEOUT_SIXTY_SECONDS);
	
	CacheWrapper::set($cacheKey, $responseJson, $gameSettings['token_expires_after'] - CacheWrapper::TIMEOUT_SIXTY_SECONDS);
	CacheWrapper::set($this->getCSRCachedTokenKey($this->gameId, $loginType, $username), $cacheKey, $gameSettings['token_expires_after']);
	echo $responseJson;
    }

    public function getToken($accountId, $username, $loginType) {
	
	$countryCodeUpdate = '';
	$sqlArgs = array(getRealIpAddr());

	$login = $this->getLoginData($username, $loginType);
	if(!empty($login)){
	    $ip = getRealIpAddr();
	    $countryCode = countryFromIP($ip);
	    if ($countryCode != $login['country']) {
		$countryCodeUpdate = ', country=?';
		$sqlArgs[] = $countryCode;
	    }
	}
	
	$userGameIds = $this->getUserGameIdsForAccount($accountId, $this->gameId);

	if (count($userGameIds) == 0) {
	    sendErrorMessage(ResponseCode::ERROR_NO_GAME_DATA_FOR_ACCOUNT);
	    $this->haltProperly();
	}

	$sqlArgs[] = $username;
	$sqlArgs[] = $loginType;
	$sql = 'UPDATE logins SET last_login=NOW(), ip_address=? ' . $countryCodeUpdate . ' WHERE username=? AND login_type=?';
	DbAuth::query($sql, $sqlArgs);

	$permissions = $this->getPermissionsByAccountId_v2($accountId, $this->gameId);
	return createToken($accountId, $userGameIds, $this->gameId, $permissions, $username, $loginType);

    }

    public function encryptToken($tokenJson) {
	$gameData = getGameData($this->gameId);
	return Encryption::encrypt($tokenJson, $gameData['vector'], $gameData['secret']);
    }

    //Remove after clients are updated
    public function addTokenToHeader($encryptedToken) {
	header("Authorization: Bearer {$encryptedToken}");
    }

    function getUserGameIdsForAccount($accountId, $gameId = null) {
	$userGamesData = $this->getGamesByAccountId($accountId, $gameId);
	$userGameIds = array();
	foreach ($userGamesData as $userGameData) {
	    $userGameIds[] = $userGameData['user_game_id'];
	}
	return $userGameIds;
    }

    public function exceedsRecentNewAccounts() {

	$limitAccountsByDevice = null;
	$limitAccountsByIp = null;

	$deviceCheckFailed = false;
	$ipCheckFailed = false;

	$gameSettings = getGameSettings($this->gameId);
	if (key_exists('max_account_by_device', $gameSettings)) {
	    $limitAccountsByDevice = $gameSettings['max_account_by_device'];
	}
	if (key_exists('max_account_by_ip', $gameSettings)) {
	    $limitAccountsByIp = $gameSettings['max_account_by_ip'];
	}

	if ($limitAccountsByDevice || $limitAccountsByIp) {
	    define('MAX_ACCOUNTS_PER_TIME_DEVICE', $gameSettings['max_account_range_device_1']); // 2
	    define('MAX_ACCOUNTS_PER_TIME_DEVICE_2', $gameSettings['max_account_range_device_2']); // 5
	    define('MAX_ACCOUNTS_PER_TIME_DEVICE_3', $gameSettings['max_account_range_device_3']); // 10

	    define('MAX_ACCOUNTS_PER_TIME_IP', $gameSettings['max_account_range_ip_1']); // 5
	    define('MAX_ACCOUNTS_PER_TIME_IP_2', $gameSettings['max_account_range_ip_2']); // 20
	    define('MAX_ACCOUNTS_PER_TIME_IP_3', $gameSettings['max_account_range_ip_3']); // 50

	    define('MAX_ACCOUNTS_PER_TIME_WINDOW', CacheWrapper::TIMEOUT_FIVE_MINUTES);
	    define('MAX_ACCOUNTS_PER_TIME_WINDOW_2', CacheWrapper::TIMEOUT_TWO_HOURS);
	    define('MAX_ACCOUNTS_PER_TIME_WINDOW_3', CacheWrapper::TIMEOUT_ONE_DAY * 30);
	}

	if ($limitAccountsByDevice) {

	    $deviceIdentifier = $this->device_id;
	    $ipAddress = getRealIpAddr();

	    //error_log("deivce_".$deviceIdentifier);

	    $timestamps = CacheWrapper::get("device_" . $deviceIdentifier);
	    //error_log(print_r($timestamps, true));


	    $newArray = array();

	    $now = time();

	    if (is_array($timestamps)) {
		$count = 0;
		$count2 = 0;
		$count3 = 0;
		foreach ($timestamps as $timestamp) {
		    if ($now - $timestamp < MAX_ACCOUNTS_PER_TIME_WINDOW) {
			$count++;
		    }
		    if ($now - $timestamp < MAX_ACCOUNTS_PER_TIME_WINDOW_2) {
			$count2++;
		    }
		    if ($now - $timestamp < MAX_ACCOUNTS_PER_TIME_WINDOW_3) {
			$count3++;
			$newArray[] = $timestamp;
		    }
		}

		if ($count > MAX_ACCOUNTS_PER_TIME_DEVICE || $count2 > MAX_ACCOUNTS_PER_TIME_DEVICE_2 || $count3 > MAX_ACCOUNTS_PER_TIME_DEVICE_3) {
		    error_log("**** DEVICE TRAPPED BY ANTI ACCOUNT CREATION SPAM FILTERS ($deviceIdentifier) ****");
		    $deviceCheckFailed = true;
		}
	    }

	    $multiplier = 1;
	    if ($deviceCheckFailed) {
		$multiplier = $gameSettings['max_account_range_ip_aggresive_multiplier'];
	    }

	    if (!$deviceCheckFailed) {
		$newArray[] = $now;
		CacheWrapper::set("device_" . $deviceIdentifier, $newArray, CacheWrapper::TIMEOUT_ONE_DAY * 30);
	    }
	}

	if ($limitAccountsByIp) {
	    //error_log("ip_".$ipAddress);

	    $timestamps = CacheWrapper::get("ip_" . $ipAddress);
	    //error_log(print_r($timestamps, true));

	    $newArray = array();

	    $now = time();

	    if (is_array($timestamps)) {
		$count = 0;
		$count2 = 0;
		$count3 = 0;

		foreach ($timestamps as $timestamp) {
		    if ($now - $timestamp < MAX_ACCOUNTS_PER_TIME_WINDOW) {
			$count++;
		    }
		    if ($now - $timestamp < MAX_ACCOUNTS_PER_TIME_WINDOW_2) {
			$count2++;
		    }
		    if ($now - $timestamp < MAX_ACCOUNTS_PER_TIME_WINDOW_3) {
			$count3++;
			$newArray[] = $timestamp;
		    }
		}

		if ($count > MAX_ACCOUNTS_PER_TIME_IP * $multiplier || $count2 > MAX_ACCOUNTS_PER_TIME_IP_2 * $multiplier || $count3 > MAX_ACCOUNTS_PER_TIME_IP_3 * $multiplier) {
		    error_log("**** IP ADDRESS TRAPPED BY ANTI ACCOUNT CREATION SPAM FILTERS ($ipAddress)  ****");
		    $ipCheckFailed = true;
		}
	    }
	    if (!$ipCheckFailed) {
		$newArray[] = $now;
		CacheWrapper::set("ip_" . $ipAddress, $newArray, CacheWrapper::TIMEOUT_ONE_DAY * 30);
	    }
	}

	if ($ipCheckFailed) {
	    return true;
	}

	return false;
    }

    function createNewAccount($gameId, $username, $password, $loginType, $verified = true, $username2 = null) {
	try {

	    $this->createAccountGDPRCheck();

	    $result = $this->getLoginData($username, $loginType);
	    $accountId = null;
	    if (!is_null($result)) {

		$accountId = $result['account_id'];
		$res = $this->getGamesByAccountId($accountId, $this->gameId);
		if (count($res) != 0) {
		    sendErrorMessage(ResponseCode::ERROR_LOGIN_ALREADY_EXISTS);
		    $this->haltProperly();
		}
	    } else {
		$accountId = $this->addAccount();
		$this->addLogin($accountId, $username, $password, $loginType, $verified, true);

		//user created account with new google play id so lets add the old one from token just incase
		if (!is_null($username2)) {
		    $this->addLogin($accountId, $username2, $password, $loginType, $verified, false);
		    error_log("adding old gp id to logins " . $username2);
		}
	    }

	    $userGameId = $this->addUserGame($accountId, $gameId);

	    $userGameConsent = new UserGameConsent($this->gameId, $accountId);
	    $this->updateAllConsents($userGameConsent);
	    $tokenJson = $this->getToken($accountId, $username, $loginType);
	    $tokenObj = json_decode($tokenJson);

	    $encryptedToken = $this->encryptToken($tokenJson);
	    $this->addTokenToHeader($encryptedToken); //Remove after clients are updated
	    $response = new stdClass();
	    $response->ok = true;
	    $response->username = $username;
	    $response->password = $password;
	    $response->account_id = $accountId;
	    $response->user_game_id = $userGameId;
	    $response->login_type = $loginType;
	    $response->time_created = time();
	    $response->access_token = $encryptedToken;
	    $response->token_type = "bearer";
	    $response->expires_at = json_decode($tokenJson)->expires_at;

	    if (property_exists($tokenObj, 'permissions'))
		$response->permissions = $tokenObj->permissions;

	    if ($this->hasParam(self::UPDATE_DEVICE)) {

		if ($this->updateDeviceInfo($userGameId))
		    $response->device_updated = true;
	    }

	    //only send refresh tokens for apple right now
	    if ($loginType == LOGIN_TYPE_APPLE) {
		//error_log("send refresh token");
		$userGameIds = $this->getUserGameIdsForAccount($accountId, $this->gameId);
		$encryptedRefreshToken = createRefreshToken($accountId, $userGameIds, $this->gameId, $username, $loginType, $this->device_id, $this->advertiser_id);
		$response->refresh_token = $encryptedRefreshToken;
	    }

	    $responseJson = json_encode($response);
	    echo $responseJson;
	} catch (Exception $e) {
	    if (isSlimException($e))
		return;

	    $response = new stdClass();
	    $response->ok = false;
	    $response->message = "Unable to create account";
	    $responseJson = json_encode($response);
	    echo $responseJson;

	    error_log($e->getTraceAsString());
	    error_log("Something very bad happened");
	    $this->haltProperly();
	}
    }

    public function createAnonAccount() {
	
	if ($this->exceedsRecentNewAccounts()) {
	    /*
	      $response = new stdClass();
	      $response->ok = false;
	      $response->message = "Too many accounts created by this IP";
	      $responseJson = json_encode($response);
	      echo $responseJson;
	     */

	    //  en/fr/de/es/it/pt/ru
	    $message = "Exceeded Maximum Accounts. Too Many Accounts Created.";
	    switch ($this->lang) {
		case 'fr':
		    $message = "Dépassé les comptes maximum. Trop de comptes créés.";
		    break;
		case 'de':
		    $message = "Überschrittene Höchstkonten. Zu viele Konten erstellt.";
		    break;
		case 'es':
		    $message = "Cuentas máximas excedidas. Demasiadas cuentas creadas.";
		    break;
		case 'it':
		    $message = "Ha superato i conti massimi. Troppi account creati.";
		    break;
		case 'pt':
		    $message = "Excedeu as contas máximas. Muitas contas criadas.";
		    break;
		case 'ru':
		    $message = "Превышено максимальное количество учетных записей. Создано слишком много учетных записей.";
		    break;
	    }
	    sendErrorMessage(ResponseCode::SERVER_MESSAGE, $message);
	    $this->haltProperly();
	}

	$username = generateRandomString(12);
	$password = generateRandomString(20);

	$this->createNewAccount($this->gameId, $username, $password, LOGIN_TYPE_ANONYMOUS);
    }

    public function createEmailAccount() {

	$username = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$this->emailChecks($username);

	$this->createNewAccount($this->gameId, $username, $password, LOGIN_TYPE_EMAIL, false);
    }

    private function emailChecks($username) {
	if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
	    sendErrorMessage(ResponseCode::ERROR_BAD_EMAIL_ADDRESS);
	    $this->haltProperly();
	}

	// check if user email is banned
	if (isEmailBanned($username)) {
	    sendErrorMessage(ResponseCode::ERROR_EMAIL_BOUNCE, ResponseCode::getMessage(ResponseCode::ERROR_EMAIL_BOUNCE));
	    $this->haltProperly();
	}

	// check if device is banned
	if (isDeviceBannedFromSendingEmail($this->platform, $this->ban_device_id, $this->device_model)) {
	    sendErrorMessage(ResponseCode::ERROR_EMAIL_MAX_FAILS, ResponseCode::getMessage(ResponseCode::ERROR_EMAIL_MAX_FAILS));
	    $this->haltProperly();
	}
    }

    public function createFacebookAccount() {

	$username = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$this->validateFacebookUser($username, $password);

	$this->createNewAccount($this->gameId, $username, $password, LOGIN_TYPE_FACEBOOK);
    }

    public function facebookAccountOptions() {

	$response = new stdClass();
	$response->ok = true;
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function createGooglePlayAccount() {

	$playerId = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$oldPlayerId = $this->googlePlayerIdChangeCheck($playerId, $password);
	$this->validateGooglePlayUser($playerId, $password);

	$this->createNewAccount($this->gameId, $playerId, "", LOGIN_TYPE_GOOGLE_PLAY, true, $oldPlayerId);
    }

    public function createAmazonAccount() {

	$playerId = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$this->validateAmazonUser($playerId, $password);

	$this->createNewAccount($this->gameId, $playerId, "", LOGIN_TYPE_AMAZON);
    }

    public function createGameCenterAccount() {

	$playerId = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$this->validateGameCenterUser($playerId, $password);

	$this->createNewAccount($this->gameId, $playerId, "", LOGIN_TYPE_GAME_CENTER);
    }

    public function createAppleAccount() {

	$playerId = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$this->validateAppleUser($playerId, $password);

	$this->createNewAccount($this->gameId, $playerId, "", LOGIN_TYPE_APPLE);
    }

    public function createSteamAccount() {

	$playerId = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$this->validateSteamUser($playerId, $password);

	$this->createNewAccount($this->gameId, $playerId, "", LOGIN_TYPE_STEAM);
    }

    // TIM: FUNCTIONS DELETE FROM HERE

    function addUserGame($accountId, $gameId) {
	$iterationCount = 1;
	$found = true;
	while ($found) {
	    $userGameId = generateRandomString(USER_GAME_ID_LENGTH);
	    try {
		$sql = "INSERT INTO user_games SET account_id=?, game=?, user_game_id=?, date_created=NOW()";
		$sqlArgs = array($accountId, $gameId, $userGameId);
		DbAuth::query($sql, $sqlArgs);
		$found = false;
	    } catch (Exception $e) {
		if (isSlimException($e))
		    return;

		error_log($e->getMessage());
		$iterationCount++;
		if ($iterationCount > MAX_RANDOM_ITERATION_COUNT) {
		    throw new Expection("Max random code generation iteration count exceeded");
		}
	    }
	}
	return $userGameId;
    }

    function addLogin($accountId, $username, $password, $loginType, $verified, $sendVerifyEmail = false) {

	if ($loginType == LOGIN_TYPE_MSM_ANONYMOUS || $loginType == LOGIN_TYPE_ANONYMOUS || $loginType == LOGIN_TYPE_EMAIL)
	    $hash = password_hash($password, PASSWORD_BCRYPT, array('cost' => 8));
	else
	    $hash = "";

	$ip = getRealIpAddr();
	$country = countryFromIP($ip);

	// PASSWORD/HASH
	$sql = 'INSERT INTO logins SET username=?, account_id=?, hash=?, login_type=?, verified=?, date_created=NOW(), last_login=NOW(), ip_address=?, country=?';
	$sqlArgs = array($username, $accountId, $hash, $loginType, $verified, $ip, $country);
	$result = DbAuth::query($sql, $sqlArgs);
	if (!$result) {
	    return false;
	} else {
	    if ($loginType == LOGIN_TYPE_EMAIL && !$verified && $sendVerifyEmail) {

		$gameSettings = getGameSettings($this->gameId);
		$gameName = $gameSettings['game_name'];
		if (!sendVerificationEmail($accountId, $username, $this->language, $this->gameId, $gameName)) {
		    logBadEmailRequest($this->platform, $this->ban_device_id, $this->device_model);
		    return false;
		}
	    }
	}
	return true;
    }

    public function bindAccount() {
	// account binding to must pass authentication
	// can bind any login as long as it is not already bound to an account
	// cannot bind accounts if the binding account already exists and the game ids are the same (one account would be lost)

	$username = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);
	$loginType = $this->reqParam(self::LOGIN_TYPE);

	$accountId = $this->authenticate($username, $password, $loginType);

	$bind_login_type = $this->reqParam(self::BIND_LOGIN_TYPE);
	$bind_username = $this->reqParam(self::BIND_USERNAME);
	$bind_password = $this->reqParam(self::BIND_PASSWORD);

	//need to check if googleplay exists under different id before getLoginData gets called
	$oldGooglePlayId = null;
	if ($bind_login_type == LOGIN_TYPE_GOOGLE_PLAY)
	    $oldGooglePlayId = $this->googlePlayerIdChangeCheck($bind_username, $bind_password);

	//check if login is already bound to an account
	$bindLogin = $this->getLoginData($bind_username, $bind_login_type);
	if (!is_null($bindLogin)) {
	    //login is bound to another account so try to merge accounts
	    $accountId2 = $this->authenticate($bind_username, $bind_password, $bind_login_type);
	    $this->mergeAccounts($accountId, $accountId2);
	    $accountId = $accountId2;
	} else {
	    if ($bind_login_type == LOGIN_TYPE_EMAIL) {

		$this->emailChecks($bind_username);

		$this->addLogin($accountId, $bind_username, $bind_password, LOGIN_TYPE_EMAIL, false, true);
	    } elseif ($bind_login_type == LOGIN_TYPE_FACEBOOK) {

		$this->validateFacebookUser($bind_username, $bind_password);
		$this->addLogin($accountId, $bind_username, $bind_password, LOGIN_TYPE_FACEBOOK, true, false);
	    } elseif ($bind_login_type == LOGIN_TYPE_GAME_CENTER) {

		$this->validateGameCenterUser($bind_username, $bind_password);
		$this->addLogin($accountId, $bind_username, $bind_password, LOGIN_TYPE_GAME_CENTER, true, false);

		$res = $this->getGamesByAccountId($accountId, $this->gameId);
		if (count($res) != 1) {
		    // found no or more than a single id, this should be bad.
		    error_log("Found more than I single user_game_id for an account and game, cannot conitnue with SQS");
		    return false;
		}
		$user_game_id = $res[0]['user_game_id'];
		$jsonString = "{'cmd':'update_gamecenter_id','gamecenter_id':'$bind_username','user_game_id':'$user_game_id'}";

		$sns = BBBSnsClient::connect(AWS_AUTH_REGION);
		BBBSnsClient::publish(AWS_CSR_SNS_TOPIC, $jsonString);

		$bind_password = "";
	    } elseif ($bind_login_type == LOGIN_TYPE_GOOGLE_PLAY) {

		$this->validateGooglePlayUser($bind_username, $bind_password);
		$this->addLogin($accountId, $bind_username, $bind_password, $bind_login_type, true, false);

		//add old google play id
		if (!is_null($oldGooglePlayId))
		    $this->addLogin($accountId, $oldGooglePlayId, $bind_password, $bind_login_type, true, false);

		$res = $this->getGamesByAccountId($accountId, $this->gameId);
		if (count($res) != 1) {
		    // found no or more than a single id, this should be bad.
		    error_log("Found more than I single user_game_id for an account and game, cannot conitnue with SQS");
		    return false;
		}
		//$user_game_id = $res[0]['user_game_id'];
		//$jsonString = "{'cmd':'update_googleplay_id','googleplay_id':'$bind_username','user_game_id':'$user_game_id'}";
		//$sns = BBBSnsClient::connect(AWS_AUTH_REGION);
		//BBBSnsClient::publish(AWS_CSR_SNS_TOPIC, $jsonString);

		$bind_password = "";
	    } elseif ($bind_login_type == LOGIN_TYPE_AMAZON) {

		$this->validateAmazonUser($bind_username, $bind_password);
		$this->addLogin($accountId, $bind_username, $bind_password, $bind_login_type, true, false);

		$res = $this->getGamesByAccountId($accountId, $this->gameId);
		if (count($res) != 1) {
		    // found no or more than a single id, this should be bad.
		    error_log("Found more than I single user_game_id for an account and game, cannot conitnue with SQS");
		    return false;
		}
		//$user_game_id = $res[0]['user_game_id'];
		//$jsonString = "{'cmd':'update_googleplay_id','googleplay_id':'$bind_username','user_game_id':'$user_game_id'}";
		//$sns = BBBSnsClient::connect(AWS_AUTH_REGION);
		//BBBSnsClient::publish(AWS_CSR_SNS_TOPIC, $jsonString);

		$bind_password = "";
	    } elseif ($bind_login_type == LOGIN_TYPE_APPLE) {

		$this->validateAppleUser($bind_username, $bind_password);
		$this->addLogin($accountId, $bind_username, $bind_password, $bind_login_type, true, false);

		$res = $this->getGamesByAccountId($accountId, $this->gameId);
		if (count($res) != 1) {
		    // found no or more than a single id, this should be bad.
		    error_log("Found more than I single user_game_id for an account and game, cannot conitnue with SQS");
		    return false;
		}
		$bind_password = "";
	    }
	}

	$response = new stdClass();
	$response->ok = true;
	$response->username = $bind_username;
	$response->password = $bind_password;
	$response->login_type = $bind_login_type;
	$response->user_game_id = $this->getUserGameId($accountId);
	$response->account_id = $accountId;

	//only send refresh tokens for apple right now
	if ($bind_login_type == LOGIN_TYPE_APPLE) {
	    //error_log("send refresh token");
	    $userGameIds = $this->getUserGameIdsForAccount($accountId, $this->gameId);
	    $encryptedRefreshToken = createRefreshToken($accountId, $userGameIds, $this->gameId, $username, $loginType, $this->device_id, $this->advertiser_id);
	    $response->refresh_token = $encryptedRefreshToken;
	}

	$responseJson = json_encode($response);
	echo $responseJson;

	return true;
    }

    function haveCommonGame($accountId1, $accountId2) {
	if ($accountId1 == $accountId2) {
	    return true;
	}
	$games1 = $this->getGamesByAccountId($accountId1);
	$games2 = $this->getGamesByAccountId($accountId2);

	$found = false;
	foreach ($games1 as $game1) {
	    foreach ($games2 as $game2) {
		if ($game1 ['game'] == $game2 ['game']) {
		    $found = true;
		}
	    }
	}
	return $found;
    }

    /* Merge can only happen if accounts have unique game ids
     * accountId1 will become accountId2
     * find all logins with accountId1 change account_id to accountId2
     * find all user_games with accountId1 change account_id to accountId2
     */

    public function mergeAccounts($accountId1, $accountId2) {
	if ($this->haveCommonGame($accountId1, $accountId2)) {
	    sendErrorMessage(ResponseCode::BIND_ERROR_GAME_CONFLICT);
	    $this->haltProperly();
	}

	$logins = $this->getLoginsByAccountId($accountId1);
	foreach ($logins as $login) {
	    $sql = 'UPDATE logins SET account_id=? WHERE id=?';
	    $sqlArgs = array($accountId2, $login['id']);
	    DbAuth::query($sql, $sqlArgs);
	}

	$games1 = $this->getGamesByAccountId($accountId1);
	foreach ($games1 as $game1) {
	    $sql = 'UPDATE user_games SET account_id=? WHERE id=?';
	    $sqlArgs = array($accountId2, $game1['id']);
	    DbAuth::query($sql, $sqlArgs);
	}

	$sql = 'DELETE FROM accounts WHERE account_id=?';
	$sqlArgs = array($accountId1);
	DbAuth::query($sql, $sqlArgs);

	$userGameConsent = new UserGameConsent($this->gameId, $accountId1);
	$userGameConsent->updateAccountId($accountId2);
    }

    public function getExistingAccounts() {
	
	$logins = $this->reqParam(self::LOGINS);
	$loginDataJson = json_decode($logins);
	$accounts = array();

	foreach ($loginDataJson as $login) {
	    //echo $login->u;
	    //echo $login->t;
	    //need to check if googleplay exists under different id before getLoginData gets called
	    if ($login->t == LOGIN_TYPE_GOOGLE_PLAY)
		$this->googlePlayerIdChangeCheck($login->u, $login->p);

	    $result = $this->getLoginData($login->u, $login->t);
	    if (!is_null($result)) {
		$accountId = $this->authenticate($login->u, $login->p, $login->t);
		$containsAccountInfo = false;
		foreach ($accounts as $account) {
		    if ($account->account_id == $accountId)
			$containsAccountInfo = true;
		}

		if (!$containsAccountInfo) {
		    $sql = "SELECT username, login_type FROM logins WHERE account_id=? AND login_type != 'anon'";
		    $sqlArgs = array($accountId);

		    $logins = DbAuth::getObjects($sql, $sqlArgs);
		    $userGamesIds = $this->getUserGameIdsForAccount($accountId, $this->gameId);

		    if (count($userGamesIds) > 0) {
			$accountData = new stdClass();
			$accountData->account_id = $accountId;
			$accountData->logins = $logins;
			$accountData->user_game_ids = $userGamesIds;

			$accounts[] = $accountData;
		    }
		}
	    }
	}

	$response = new stdClass();
	$response->ok = true;
	$response->accounts = json_encode($accounts);
	//$response->logins = $logins;
	//$response->user_game_ids = $userGamesIds;
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    function getSecureAccountsByDevice($advertiser_id, $platform, $device_model, $device_vendor, $gameId) {
	$sql = "SELECT account_id, login_type, username FROM logins WHERE account_id IN (SELECT account_id FROM user_game_devices JOIN user_games ON user_game_devices.user_game_id = user_games.user_game_id WHERE device_fk IN (SELECT id FROM devices WHERE advertiser_id=? AND platform=? AND device_model=? AND device_vendor=?) AND game=? AND verified=1) AND login_type != 'anon' ORDER BY last_login DESC";
	$sqlArgs = array($advertiser_id, $platform, $device_model, $device_vendor, $gameId);
	return DbAuth::getObjects($sql, $sqlArgs);
    }

    public function findExistingAccount() {
	
	$advertiser_id = $this->advertiser_id;
	$platform = $this->platform;
	$device_model = $this->device_model;
	$device_vendor = $this->device_vendor;
	$gameId = $this->gameId;

	// look for an existing device based on valid IDFA
	if (!validGUID($advertiser_id)) {
	    //error_log("findExistingAccount(): Invalid IDFA " . $advertiser_id);
	    sendOkMessage();
	    $this->haltProperly();
	}

	$MAX_ACCOUNTS_PER_DEVICE_REENGAGEMENT = 2; // FIX better number?
	// get accounts for this device
	$accounts = $this->getSecureAccountsByDevice($advertiser_id, $platform, $device_model, $device_vendor, $gameId);
	$numAccounts = count($accounts);
	if ($numAccounts == 0) {
	    //error_log("findExistingAccount(): No accounts for device with IDFA " . $advertiser_id);
	    sendOkMessage();
	    $this->haltProperly();
	} else if ($numAccounts > $MAX_ACCOUNTS_PER_DEVICE_REENGAGEMENT) {
	    //error_log("findExistingAccount(): Too many accounts for device with IDFA " . $advertiser_id . " (" . $numAccounts . ")" );
	    sendOkMessage();
	    $this->haltProperly();
	}

	// assume first (most recent as returned by getSecureAccountsByDeviceId) is what they want
	$account = reset($accounts);

	// FIX fire off metric indicating a re-engagement for this user
	// send login_type and possibly username (if email) to client
	$data = array('login_type' => $account['login_type']);
	if ($account['login_type'] === 'email')
	    $data['username'] = $account['username'];
	sendOkMessage($data);
	$this->haltProperly();
    }

    public function deleteAccount() {
	$username = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);
	$loginType = $this->reqParam(self::LOGIN_TYPE);

	$accountId = $this->authenticate($username, $password, $loginType);

	$sql = "DELETE FROM logins WHERE account_id=?";
	$sqlArgs = array($accountId);
	$result = DbAuth::query($sql, $sqlArgs);

	$sql = "DELETE FROM accounts WHERE account_id=?";
	$result = DbAuth::query($sql, $sqlArgs);

	$sql = "DELETE FROM user_games WHERE account_id=?";
	$result = DbAuth::query($sql, $sqlArgs);

	$response = new stdClass();
	$response->ok = true;
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function resendVerifyEmail() {
	$username = $this->reqParam(self::USERNAME);

	$sql = "SELECT account_id FROM logins WHERE username=? AND login_type=?";
	$sqlArgs = array($username, LOGIN_TYPE_EMAIL);
	$result = DbAuth::getObject($sql, $sqlArgs);
	if (!$result) {
	    sendErrorMessage(ResponseCode::AUTH_ERROR_USERNAME);
	    $this->haltProperly();
	}
	$accountIdFromDb = $result['account_id'];

	$this->emailChecks($username);

	$gameSettings = getGameSettings($this->gameId);
	$gameName = $gameSettings['game_name'];

	if (!sendVerificationEmail($accountIdFromDb, $username, $this->language, $this->gameId, $gameName)) {
	    sendErrorMessage(ResponseCode::ERROR_EMAIL_BOUNCE, ResponseCode::getMessage(ResponseCode::ERROR_EMAIL_BOUNCE));
	    $this->haltProperly();
	}

	$res = new stdClass();
	$res->ok = true;

	$json = json_encode($res);
	echo $json;
	$this->haltProperly();
    }

    public function getAnonFromMsmAnon() {
	$username = $this->reqParam(self::USERNAME);
	$password = $this->reqParam(self::PASSWORD);

	$accountId = $this->authenticate($username, $password, LOGIN_TYPE_MSM_ANONYMOUS);

	//check conversion table first for msm anon
	$sql = 'SELECT new_anon FROM msm_anon_conversion WHERE msm_anon=?';
	$sqlArgs = array($username);
	$result = DbAuth::getObject($sql, $sqlArgs);

	$new_username = null;
	$new_password = null;

	//if found create new password, update login password
	if ($result) {

	    $new_username = $result['new_anon'];
	    $new_password = generateRandomString(20);

	    $new_password_hash = password_hash($new_password, PASSWORD_BCRYPT, array('cost' => 8));

	    $sql = 'UPDATE logins SET hash=? WHERE username=?';
	    $sqlArgs = array($new_password_hash, $new_username);
	    DbAuth::query($sql, $sqlArgs);
	} else {
	    //else create new anon login for user and save in conversion table
	    $new_username = generateRandomString(12);
	    $new_password = generateRandomString(20);

	    if ($this->addLogin($accountId, $new_username, $new_password, LOGIN_TYPE_ANONYMOUS, true, false)) {
		$sql = "INSERT INTO msm_anon_conversion SET msm_anon=?, new_anon=?, date_converted=NOW()";
		$sqlArgs = array($username, $new_username);
		DbAuth::query($sql, $sqlArgs);
	    }
	}

	$res = new stdClass();
	$res->ok = true;
	$res->username = $new_username;
	$res->password = $new_password;

	$json = json_encode($res);
	echo $json;
	$this->haltProperly();
    }

    private function removeMsmAnon($username) {
	$sql = 'SELECT msm_anon FROM msm_anon_conversion WHERE new_anon=?';
	$sqlArgs = array($username);
	$result = DbAuth::getObject($sql, $sqlArgs);

	//if found remove
	if ($result) {

	    $msm_username = $result['msm_anon'];

	    $sql = "DELETE FROM logins WHERE username=? AND login_type='msm_anon'";
	    $sqlArgs = array($msm_username);
	    $result = DbAuth::query($sql, $sqlArgs);

	    $sql = "DELETE FROM msm_anon_conversion WHERE msm_anon=?";
	    $sqlArgs = array($msm_username);
	    $result = DbAuth::query($sql, $sqlArgs);
	}
    }

    public function getGameConfig() {
	
	$platform = $this->reqParam('platform');

	$gameConfig = file_get_contents(GAME_CONFIG_DIR . $this->gameId . '.json');
	$json = json_decode($gameConfig, true);

	$platformConfigs = $json['platforms'];
	$platformConfig = null;
	foreach ($platformConfigs as $config) {
	    if ($config['type'] == $platform) {
		$platformConfig = $config;
	    }
	}

	if ($platformConfig == null) {
	    sendErrorMessage(ResponseCode::AUTH_GAME_CONFIG_NOT_FOUND, ResponseCode::getMessage(ResponseCode::AUTH_GAME_CONFIG_NOT_FOUND) . $platform);
	    $this->haltProperly();
	}

	if ($this->AuthVersionSupportsGDPR() && UserGameConsent::doesGameRequireConsent($this->gameId, "gdpr_all_consent")) {
	    $platformConfig['gdpr_consent_required'] = true;
	}

	if (array_key_exists("age_gate_consent_required", $json)) {
	    $platformConfig['age_gate_consent_required'] = $json['age_gate_consent_required'];
	}

	$res = new stdClass();
	$res->ok = true;
	$res->config = $platformConfig;

	$json = json_encode($res);
	echo $json;
	$this->haltProperly();
    }

    private function updateAllConsents($userGameConsent) {
	if ($this->hasParam("consent")) {
	    $consentList = json_decode($this->reqParam("consent"), true);
	    $userGameConsent->updateConsents($consentList);
	}
    }

    private function hasConsentParam($consentParam) {
	if ($this->hasParam("consent")) {
	    $consentList = json_decode($this->reqParam("consent"), true);
	    foreach ($consentList as $consent) {
		if ($consent == $consentParam)
		    return true;
	    }
	}
	return false;
    }

    private function createAccountGDPRCheck() {
	if ($this->AuthVersionSupportsGDPR() && UserGameConsent::doesGameRequireConsent($this->gameId, "gdpr_all_consent") && !$this->hasConsentParam("gdpr_all_consent")) {
	    $this->GDPRConsentError();
	}
    }

    private function checkGDPRConsent($accountId) {
	if ($this->AuthVersionSupportsGDPR()) {
	    $userGameConsent = new UserGameConsent($this->gameId, $accountId);
	    $this->updateAllConsents($userGameConsent);
	    if ($userGameConsent->requiresConsent("gdpr_all_consent")) {
		$this->GDPRConsentError();
	    }
	}
    }

    private function GDPRConsentError() {
	sendErrorMessage(ResponseCode::AUTH_GDPR_CONSENT_REQUIRED, ResponseCode::getMessage(ResponseCode::AUTH_GDPR_CONSENT_REQUIRED));
	$this->haltProperly();
    }

    private function AuthVersionSupportsGDPR() {
	if (!is_null($this->auth_version) && version_compare($this->auth_version, self::GDPR_AUTH_VERSION, '>=')) {
	    return true;
	}
	return false;
    }
    
    // MFA Functions
    public function getMfaQr(){
	$ugId = $this->reqParam('ugid');
	$gameId = $this->reqParam(SELF::GAME_ID);
	$username = $this->reqParam(SELF::USERNAME);
	$password = $this->reqParam(SELF::PASSWORD);
	
	// this should fault out if the username/password doesn't match our records
	$this->authenticate($username, $password, 'email');
	
	$accountId = null;
	
	$sql = 'SELECT account_id FROM user_games WHERE user_game_id=?';
	$sqlArgs = array($ugId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	if (!$result) {
	    $response = new stdClass();
	    $response->ok = false;
	    $response->message = "Account not found";
	    $json = json_encode($response);
	    echo $json;	
	    die();
	}
	$accountId = $result['account_id'];
	
	$g = new \Sonata\GoogleAuthenticator\GoogleAuthenticator();

	$secret = $this->generateMfaSecret($g, $accountId);
	
	$qr = \Sonata\GoogleAuthenticator\GoogleQrUrl::generate($username, $secret, MFA_NAME);
	
	$trimmedCacheKey = $gameId . '-email-' . trim($username) . '-' . $password;
	$cacheKey = md5($trimmedCacheKey);
	CacheWrapper::delete($cacheKey);	
		
	$response = new stdClass();
	$response->ok = true;
	$response->qr = $qr;
	$json = json_encode($response);
	echo $json;
	
    }
    
    public function mfaSetupConfirmation(){
	$ugId = $this->reqParam('ugid');
	$code = $this->reqParam(self::MFA_CODE);
	
	$response = new stdClass();

	if($this->verifyMfa($ugId, $code)){
	    $response->ok = true;
	    
	    $sql = 'SELECT account_id FROM user_games WHERE user_game_id=?';
	    $sqlArgs = array($ugId);
	    $result = DbAuth::getObject($sql, $sqlArgs);
	    if (!$result) {
		$response = new stdClass();
		$response->ok = false;
		$response->message = "Account not found";
		$json = json_encode($response);
		echo $json;	
		die();
	    }
	    $accountId = $result['account_id'];
	    
	    DbAuth::query("UPDATE login_mfas SET confirmed=1 WHERE account_id=?", array($accountId));
	    
	}else{
	    $response->ok = false;
	    $response->message = "Invalid or expired code";
	}

        $json = json_encode($response);
	echo $json;	
	
    }
    
    public function verifyMfaCode(){
	$ugId = $this->reqParam('ugid');
	$code = $this->reqParam(self::MFA_CODE);
	
	$response = new stdClass();
	if($this->verifyMfa($ugId, $code)){
	    $response->ok = true;
	}else{
	    $response->ok = false;
	    $response->message = "Invalid or expired code";
	}
	$json = json_encode($response);
	echo $json;	    
    }
    private function generateMfaSecret($g, $accountId){
	$secret = $g->generateSecret();
	DbAuth::query("INSERT INTO login_mfas SET account_id=?, secret=?, confirmed=0 ON DUPLICATE KEY UPDATE secret=?", array($accountId, $secret, $secret));
	return $secret;
    }
    
    private function verifyMfa($ugId, $code){
	$secret = $this->getMfaSecret($ugId);
	
	$g = new \Sonata\GoogleAuthenticator\GoogleAuthenticator();
	return $g->checkCode($secret, $code);	
    }
    
    private function getMfaSecret($ugId){
	// get the account_id 
	$sql = 'SELECT account_id FROM user_games WHERE user_game_id=?';
	$sqlArgs = array($ugId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	if (!$result) {
	    $response = new stdClass();
	    $response->ok = false;
	    $response->message = "Account not found";
	    $json = json_encode($response);
	    echo $json;	
	    die();
	}
	$accountId = $result['account_id'];
	
	$sql = 'SELECT secret FROM login_mfas WHERE account_id=?';
	$sqlArgs = array($accountId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	if (!$result) {
	    $response = new stdClass();
	    $response->ok = false;
	    $response->message = "Account secret not found";
	    $json = json_encode($response);
	    echo $json;	
	    die();
	}

	return $result['secret'];
    }
}
