<?php

class ControllerBase {

    const GAME_ID = 'g';
    const EMAIL_ADDRESS = 'e';
    const USERNAME = 'u';
    const PASSWORD = 'p';
    const LOGIN_TYPE = 't';    
    const MFA_CODE = 'mfa';

    protected $app;
    protected $request;
    protected $response;
    protected $gameId;

    public function setApp($app) {
	$this->app = $app;
    }

    public function haltProperly($value = null, $responseCode = null) {
	if ($responseCode != null)
	    $app->response->setStatus($responseCode);

	if ($value != null)
	    echo( $value );

	$this->app->stop();
    }

    public function setRequest($request) {
	$this->request = $request;
    }

    public function setResponse($response) {
	$this->response = $response;
    }

    public function hasParam($name) {
	return !is_null($this->request->params($name));
    }

    public function reqParam($name) {
	$param = $this->request->params($name);

	if (is_null($param)) {
	    error_log("Missing param " . $name);
	    sendErrorMessage(ResponseCode::AUTH_ERROR_MISSING_DATA);
	    $this->haltProperly();
	} else
	    return $param;
    }

    protected function isClientToken() {
	if (!isset($this->token->permissions->is_server) || !$this->token->permissions->is_server) {
	    return true;
	}
	return false;
    }

    protected function isServerToken() {
	if (isset($this->token->permissions->is_server) && !empty($this->token->permissions->is_server) && $this->token->permissions->is_server) {
	    return true;
	}
	return false;
    }

    protected function requireToken() {
	if (is_null($this->token)) {
	    error_log("failed to have a required token");
	    sendErrorMessage(ResponseCode::AUTH_TOKEN_MISSING);
	    $this->haltProperly();
	}
    }

    protected function requireClientToken() {
	$this->requireToken();
	if (!$this->isClientToken()) {
	    error_log("failed to have a client token");
	    sendErrorMessage(ResponseCode::AUTH_INVALID_CLIENT_TOKEN);
	    $this->haltProperly();
	}
    }

    protected function requireServerToken() {
	$this->requireToken();
	if (!$this->isServerToken()) {
	    error_log("failed to have a server token");
	    sendErrorMessage(ResponseCode::AUTH_INVALID_SERVER_TOKEN);
	    $this->haltProperly();
	}
    }

    protected function getEncryptedToken() {
	$encryptedString = null;
	if (isset($_REQUEST['access_token']) && !empty($_REQUEST['access_token'])) {
	    $tokenData = json_decode($_REQUEST['access_token']);
	    $encryptedString = $tokenData->access_token;
	} else {
	    foreach (getallheaders() as $name => $value) {
		if (strtolower($name) == 'authorization' || strtolower($name) == 'bearer') {
		    list($subname, $encryptedString) = explode(' ', $value); // break up the "Bearer encryptedStringHere" header
		}
	    }
	}
	return $encryptedString;
    }

    protected function getDecryptedToken($encrypedToken) {
	$gameData = getGameData($this->gameId);
	return Encryption::decrypt($encrypedToken, $gameData['vector'], $gameData['secret']);
    }

    protected function getDecodedToken($decryptedToken) {
	$token = json_decode($decryptedToken);
	return $token;
    }

    // Depricated
    /*
    public function getPermissionsByAccountId($accountId) {
	$sql = "SELECT permissions FROM accounts WHERE account_id=?";
	$sqlArgs = array($accountId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	$resultArray = json_decode($result['permissions']);
	return $resultArray;
    }
    */
    
    public function getPermissionsByAccountId_v2($accountId, $gameId) {
	$sql = 'SELECT game, name as permission 
			FROM account_game_permissions, game_permissions 
			WHERE account_game_permissions.account_id=? 
			AND account_game_permissions.game_permission_id=game_permissions.game_permission_id ';
	if ($gameId == null)
	    $sql .= 'AND game IS NULL';
	else
	    $sql .= 'AND game=?';

	$sqlArgs = $gameId == null ? array($accountId) : array($accountId, $gameId);
	$results = DbAuth::getObjects($sql, $sqlArgs);

	if ($results != null && count($results) > 0) {
	    $permissions = new stdClass();
	    foreach ($results as $row) {
		//$permissions->$row['permission'] = true; // this only works below PHP 7
		$permissionName = $row['permission'];
		$permissions->$permissionName = true;
	    }
	    return $permissions;
	}
	return null;
    }

    protected function canManageAccounts($response) {
	$token = null;
	$permissions = null;
	foreach (getallheaders() as $name => $value) {
	    if (strtolower($name) == 'authorization') {
		$data = explode(' ', $value);
		$token = $data[1];
	    }
	}
	if (!is_null($token)) {
	    $gameData = getGameData($this->gameId);
	    $decryptedToken = json_decode(Encryption::decrypt($token, $gameData['vector'], $gameData['secret']));
	    $accountId = $decryptedToken->account_id;
	    $permissions = $this->getPermissionsByAccountId_v2($accountId, $this->gameId);
	    // WTF, why is this here !!
	    /*
	} else {
	    $username = $this->reqParam(self::USERNAME);
	    $password = $this->reqParam(self::PASSWORD);
	    $loginType = $this->reqParam(self::LOGIN_TYPE);

	    $accountId = $this->authenticate($username, $password, $loginType);
	    */
	}

	// Check if this person has permission to make these changes
	if (is_null($permissions) || !is_object($permissions) || !property_exists($permissions, "manage_accounts") || !$permissions->manage_accounts) {
	    $this->haltProperly(json_encode($response));
	}

	return $accountId; // used by some functions for tracking who changed what 
    }

    protected function hasPermission($response, $reqPermission, $gameId, $failOnMissing) {
	$token = null;
	$permission = null;
	foreach (getallheaders() as $name => $value) {
	    if (strtolower($name) == 'authorization') {
		$data = explode(' ', $value);
		$token = $data[1];
	    }
	}

	if (!is_null($token)) {
	    $gameData = getGameData($this->gameId);
	    $decryptedToken = json_decode(Encryption::decrypt($token, $gameData['vector'], $gameData['secret']));

	    if (!is_object($decryptedToken) || time() > $decryptedToken->expires_at) {
		sendErrorMessage(ResponseCode::AUTH_TOKEN_EXPIRED);
		$this->haltProperly();
	    }

	    $accountId = $decryptedToken->account_id;
	    /*
	} else {
	    $username = $this->reqParam(self::USERNAME);
	    $password = $this->reqParam(self::PASSWORD);
	    $loginType = $this->reqParam(self::LOGIN_TYPE);

	    $accountId = $this->authenticate($username, $password, $loginType);
	    */

	    // Check if this person has permission to make these changes
	    $sql = 'SELECT game, name 
			    FROM account_game_permissions, game_permissions 
			    WHERE account_game_permissions.account_id=? 
			    AND account_game_permissions.game_permission_id=game_permissions.game_permission_id ';
	    if ($gameId == null)
		$sql .= 'AND game IS NULL';
	    else
		$sql .= 'AND game=?';

	    $sqlArgs = $gameId == null ? array($accountId) : array($accountId, $gameId);
	    $results = DbAuth::getObjects($sql, $sqlArgs);
	    if (!$results) {
		if ($failOnMissing) {
		    $this->haltProperly(json_encode($response));
		}

		return null;
	    }

	    foreach ($results as $permission) {
		if ($permission['name'] == $reqPermission) {
		    return $accountId;
		}
	    }
	}

	if ($failOnMissing) {
	    $this->haltProperly(json_encode($response));
	}

	return null;
    }

    protected function getLoginsForUserGameId($userGameId) {

	$sql = "SELECT account_id FROM user_games WHERE user_game_id=? AND game=?";
	$sqlArgs = array($userGameId, $this->gameId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	if(!$result){
	    return array();
	}
	$accountId = $result['account_id'];

	$sql = "SELECT * FROM logins WHERE account_id=?";
	$sqlArgs = array($accountId);

	return DbAuth::getObjects($sql, $sqlArgs);
    }

    protected function getCSRCachedTokenKey($gameId, $loginType, $username) {
	return "csr-user-cached-token-key-{$gameId}-{$loginType}-" . trim($username);
    }

    protected function clearCachedTokensForUserGameId($userGameId) {
	$logins = $this->getLoginsForUserGameId($userGameId);

	foreach ($logins as $login) {

	    $loginType = $login['login_type'];
	    $username = $login['username'];
	    $this->clearCachedToken($this->gameId, $loginType, $username);
	}
    }

    protected function clearCachedToken($gameId, $loginType, $username) {

	$csrCacheKey = $this->getCSRCachedTokenKey($gameId, $loginType, $username);
	$cacheKey = CacheWrapper::get($csrCacheKey);

	if (!empty($cacheKey)) {
	    CacheWrapper::delete($cacheKey);
	    CacheWrapper::delete($csrCacheKey);
	}
    }

}
