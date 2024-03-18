<?php
class SupportController extends ControllerBase {

    use Authentication;

    const USER_GAME_ID = 'user_game_id';

    protected $encryptedToken;
    protected $decryptedToken;
    protected $token;

    public function init() {
	$this->gameId = $this->reqParam(parent::GAME_ID);
	$this->encryptedToken = $this->getEncryptedToken();
	$this->decryptedtoken = $this->getDecryptedToken($this->encryptedToken);
	$this->token = $this->getDecodedToken($this->decryptedtoken);
    }

    public function updateEmailLogin() {
	$response = new stdClass();
	$response->result = false;
	
	$this->canManageAccounts($response);      //Check Permissions
	
	$newEmail = $this->reqParam("new_email");
	$accountId = $this->reqParam("account_id");
	$lang = $this->reqParam("lang");
	$gameId = $this->reqParam("game_id");
	$gameName = $this->reqParam("game_name");
	if (empty($newEmail) || empty($accountId) || !filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {   //Validate that an email was passed in the query and has a valid format
	    $response->message = "Email Address or Account Id is Invalid!";
	    $this->haltProperly(json_encode($response));
	} else {
	    $sql = "SELECT verified FROM logins WHERE login_type = 'email' AND account_id = ? LIMIT 1"; //Find the verified status of users existing email
	    $args = array($accountId);
	    $result = DbAuth::GetObject($sql, $args);

	    if (!is_null($result)) {  //Check to see if the account that wants their email swapped is already verified
		if ($result['verified']) {  //Potentially not needed or wanted. If their email is verified, then they have access to that "wrong" email account and something fishy might be happening
		    $response->message = "The email for this account has already been verified, they can't be manually swapped to another!";
		    $this->haltProperly(json_encode($response));
		}
	    } else {  //If you can't find the login data for the current account, there is no email address to switch in the first place
		$response->message = "No record was found for this accounts login data!";
		$this->haltProperly(json_encode($response));
	    }

	    $sql = "SELECT verified FROM logins WHERE login_type = 'email' AND username = ? LIMIT 1";   //Check to see if a record with that email already exists
	    $args = array($newEmail);								   //Could possibly combine this query with the top one, but then we'd lose detail on the error message.
	    $result = DbAuth::GetObject($sql, $args);

	    if (!is_null($result)) { //If it already exists, check if it's verified or not. Either way that email cannot be used with another account
		if ($result['verified']) {
		    $response->message = "This email is already bound and verified!";
		    $this->haltProperly(json_encode($response));
		} else {
		    $response->message = "This email is bound, but has not been verified yet.";
		    $this->haltProperly(json_encode($response));
		}
	    } else {
		$sql = "UPDATE logins SET username = ? WHERE account_id = ? AND login_type = 'email'";   //Otherwise if the email doesn't exist anywhere, and it's valid, it can be used with that account
		$args = array($newEmail, $accountId);
		if (!DbAuth::query($sql, $args)) {
		    $response->message = "Update Failed";
		    $this->haltProperly(json_encode($response));
		} else {
		    try {
			if (!sendVerificationEmail($accountId, $newEmail, $lang, $gameId, $gameName)) {  //Automatically send a verification prompt to the new email address
			    $response->message = "Update successful, but verification email failed to send.";
			    $this->haltProperly(json_encode($response));
			}
		    } catch (Exception $e) {
			$response->message = $e->getMessage();
			$this->haltProperly(json_encode($response));
		    }
		    $response->result = true; //Everything worked out ok and the accounts email has been changed to the new one
		    $this->haltProperly(json_encode($response));
		}
	    }
	}
    }

    public function sendPasswordRecoveryEmailForCET() {
	$username = $this->reqParam(self::USERNAME);

	if (!sendPasswordRecoveryEmailForCET($username)) {
	    sendErrorMessage(ResponseCode::GENERAL_ERROR, ResponseCode::getMessage(ResponseCode::GENERAL_ERROR));
	    $this->haltProperly();
	}

	$res = new stdClass();
	$res->ok = true;

	$json = json_encode($res);
	echo $json;
	$this->haltProperly();
    }
    
    
    //Used to track down lost accounts by finding related devices/accounts across every game.
    public function getExtendedDevices() {
	$response = new stdClass();
	$response->result = false;
	
	//Validate just MSM manage accounts, even though other game data could be pulled from the query.
	$this->canManageAccounts($response);
	
	$userGameIds = $this->request->getBody();
	$userGameIds = mysqli_real_escape_string(DbAuth::db(), $userGameIds);   //Can't use positional parameters with the IN clause
	$userGameIds = explode(",", $userGameIds);
	$userGameIds = implode("','", $userGameIds);
	$sql = "SELECT logins.*, user_games.game, user_games.user_game_id, user_games.client_version, user_games.login_count, user_games.date_created AS game_date_created, user_games.last_login AS game_last_login, devices.device_id, devices.advertiser_id, devices.platform, devices.device_model, devices.device_vendor, devices.os_version, devices.ip, devices.date_installed, user_game_devices.device_fk, user_game_devices.auth_version, user_game_devices.date_created AS user_device_date_created, user_game_devices.last_played
		FROM logins, user_games, user_game_devices, devices, devices AS d2, user_game_devices AS ud2 
		WHERE ud2.user_game_id IN ('" . $userGameIds . "')
		AND ud2.device_fk=d2.id 
		AND (d2.device_id=devices.device_id 
		AND (NOT d2.device_id IN('', '00000000-0000-0000-0000-000000000000', '00000000', 'UNSUPPORTED')) 
		AND d2.device_id IS NOT NULL) 
		AND devices.id=user_game_devices.device_fk 
		AND user_game_devices.user_game_id=user_games.user_game_id 
		AND logins.account_id=user_games.account_id
		GROUP BY logins.id, user_games.id, user_game_devices.id
		LIMIT 100;";
	$sqlArgs = array($userGameIds);
	$deviceResults = DbAuth::getObjects($sql);
	$response->result = true;
	$response->users = $deviceResults;
	echo json_encode($response);
    }

    public function getDevices() {
	$response = new stdClass();
	$response->result = false;

	$this->canManageAccounts($response);

	$userGameId = $this->reqParam(self::USER_GAME_ID);

	$sql = "SELECT * FROM user_game_devices WHERE user_game_id=?";
	$sqlArgs = array($userGameId);

	$resultDeviceIds = DbAuth::getObjects($sql, $sqlArgs);

	$deviceIds = array();

	foreach ($resultDeviceIds as $deviceId) {
	    $deviceIds[] = ($deviceId['device_fk']);
	}
	$devices = array();
	if (count($deviceIds)) {
	    $deviceIdString = implode($deviceIds, ',');
	    $sql = "SELECT * FROM devices WHERE id IN(" . $deviceIdString . ")";
	    $resultDevices = DbAuth::getObjects($sql);

	    foreach ($resultDevices as $device) {

		$deviceData = new stdClass();
		$deviceData->device_id = $device['device_id'];
		$deviceData->advertiser_id = $device['advertiser_id'];
		$deviceData->device_model = $device['device_model'];
		$deviceData->device_vendor = $device['device_vendor'];
		$deviceData->os_version = $device['os_version'];
		$deviceData->ip = $device['ip'];
		$deviceData->date_installed = $device['date_installed'];

		$devices[] = $deviceData;
	    }
	}

	$response = new stdClass();
	$response->ok = true;
	$response->devices = json_encode($devices);
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function getDeviceUserGameIds() {
	$response = new stdClass();
	$response->result = false;

	$this->canManageAccounts($response);

	$deviceId = $this->reqParam("device_id");
	
	if(substr($deviceId, 0, 7) == '00000000'){
	    error_log("CAUGHT SUPPORT REQUEST FOR BAD DEVICE ID");
	    $responseJson = json_encode($response);
	    echo $responseJson;
	    return;
	}
	
	$sql = "SELECT id FROM devices WHERE device_id=?";
	$sqlArgs = array($deviceId);
	$resultIds = DbAuth::getObjects($sql, $sqlArgs);

	$ids = '';
	$devices = array();
	foreach ($resultIds as $id) {

	    if ($ids != '')
		$ids .= ',';

	    $ids .= ($id['id']);
	}

	$sql = "SELECT DISTINCT user_game_id FROM user_game_devices WHERE device_fk IN(" . $ids . ")";
	$resultUserGameIds = DbAuth::getObjects($sql);

	$userGameIdsString = "";
	foreach ($resultUserGameIds as $userGameId) {

	    if ($userGameIdsString != '')
		$userGameIdsString .= ',';
	    $userGameIdsString .= '"' . $userGameId['user_game_id'] . '"';
	}

	//remove user_game_ids that don't play this game
	$sql = "SELECT user_game_id FROM user_games WHERE user_game_id IN(" . $userGameIdsString . ") AND game=?";
	$resultUserGameIds = DbAuth::getObjects($sql, array($this->gameId));

	$userGameIds = array();
	foreach ($resultUserGameIds as $userGameId) {

	    $userGameIds[] = $userGameId['user_game_id'];
	}

	$response = new stdClass();
	$response->ok = true;
	$response->user_game_ids = json_encode($userGameIds);
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function getLogins() {

	$response = new stdClass();
	$response->ok = false;
	
	$this->isAdmin($response, $this->gameId);
	
	$userGameId = $this->reqParam("user_game_id");

	// $accountId = $this->getAccountIdFromUserGameId($userGameId);

	$logins = $this->getLoginsForUserGameId($userGameId);

	$resultLogins = array();

	foreach ($logins as $login) {

	    $loginData = new stdClass();
	    $loginData->id = $login['id'];
	    $loginData->account_id = $login['account_id'];
	    $loginData->login_type = $login['login_type'];
	    $loginData->username = $login['username'];
	    $loginData->hash = $login['hash'];
	    $loginData->verified = $login['verified'];
	    $loginData->last_login = $login['last_login'];
	    $loginData->date_created = $login['date_created'];
	    $loginData->migrated_on = $login['migrated_on'];
	    $loginData->ip_address = $login['ip_address'];
	    $loginData->country = $login['country'];


	    $resultLogins[] = $loginData;
	}

	$response->ok = true;
	$response->logins = json_encode($resultLogins);
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function getUserGames() {
	$response = new stdClass();
	$response->ok = false;
	
	$this->isAdmin($response, $this->gameId);

	$accountId = $this->reqParam("account_id");

	$sql = "SELECT * FROM user_games WHERE account_id=?";
	$result = DbAuth::getObjects($sql, array($accountId));

	$games = array();
	foreach ($result as $userGame) {
	    $data = new stdClass();
	    $data->userGameId = $userGame['user_game_id'];
	    $data->gameId = $userGame['game'];
	    $games[] = $data;
	}

	$response->ok = true;
	$response->data = json_encode($games);
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function swapLogins() {
	$response = new stdClass();
	$response->result = false;

	$adminAccountId = $this->canManageAccounts($response);

	$userGameId1 = $this->reqParam('user_game_id_1');
	$userGameId2 = $this->reqParam('user_game_id_2');

	if (is_null($userGameId1) || is_null($userGameId2)) {
	    $this->haltProperly(json_encode($response));
	}

	$sql = "UPDATE user_games SET user_game_id = ? WHERE user_game_id = ?";
	if (!DbAuth::query($sql, array("temp_UGID", $userGameId1))) {
	    $this->haltProperly(json_encode($response));
	}
	if (!DbAuth::query($sql, array($userGameId1, $userGameId2))) {
	    DbAuth::query($sql, array($userGameId1, "temp_UGID"));

	    $this->haltProperly(json_encode($response));
	}
	if (!DbAuth::query($sql, array($userGameId2, "temp_UGID"))) {
	    DbAuth::query($sql, array($userGameId2, $userGameId1));
	    DbAuth::query($sql, array($userGameId1, "temp_UGID"));

	    $this->haltProperly(json_encode($response));
	}
	$sql = "INSERT INTO account_swap_log(old_account_id, new_account_id, login_id, swapped_by, swapped_on)
		SELECT (SELECT account_id FROM user_games WHERE user_game_id=? LIMIT 1) AS old_account_id, 
		(SELECT account_id FROM user_games WHERE user_game_id=? LIMIT 1) AS new_account_id, 
		(SELECT logins.id FROM logins, user_games WHERE user_game_id=? AND logins.account_id= user_games.account_id LIMIT 1)AS login_id, 
		? AS swapped_by, NOW() AS swapped_on";
	if (!DbAuth::query($sql, array($userGameId1, $userGameId2, $userGameId1, $adminAccountId))) {
	    $this->haltProperly(json_encode($response));
	}
	if (!DbAuth::query($sql, array($userGameId2, $userGameId1, $userGameId2, $adminAccountId))) {
	    $this->haltProperly(json_encode($response));
	}

	$this->clearCachedTokensForUserGameId($userGameId1);
	$this->clearCachedTokensForUserGameId($userGameId2);

	header("Content-Type: application/json; charset=utf-8");
	$response->result = true;
	echo json_encode($response);
    }

    public function linkLogins() {
	$response = new stdClass();
	$response->result = false;
	$response->reason = 'Unsupported Method';

	$this->haltProperly(json_encode($response));
    }

    public function updateAccountId() {

	$response = new stdClass();
	$response->ok = false;

	$adminAccountId = $this->canManageAccounts($response);

	$newAccountId = $this->reqParam('new_account_id');
	$username = $this->reqParam('username');
	$loginType = $this->reqParam('login_type');


	try {
	    $sql = "SELECT * FROM logins WHERE username=? AND login_type=?";
	    $result = DbAuth::getObject($sql, array($username, $loginType));
	    if ($result) {
		$oldAccountId = $result['account_id'];
		$loginId = $result['id'];
	    }


	    // if either of the accounts have permissions associated with them, cancel this task
	    if (!empty($this->getPermissionsByAccountId_v2($oldAccountId, $this->gameId)) || !empty($this->getPermissionsByAccountId_v2($newAccountId, $this->gameId))) {
		$response->message = 'At least one of the accounts has admin permissions associated. please contact the Game Admin for assistance.';
		$responseJson = json_encode($response);
		$this->haltProperly($responseJson);
	    }


	    DbAuth::query("INSERT INTO account_swap_log SET old_account_id=?, new_account_id=?, login_id=?, swapped_by=?, swapped_on=NOW()", array($oldAccountId, $newAccountId, $loginId, $adminAccountId));

	    $sql = "UPDATE logins SET account_id=? WHERE username=? AND login_type=?";
	    $args = array($newAccountId, $username, $loginType);
	    DbAuth::query($sql, $args);

	    $sql = "SELECT * FROM user_games WHERE account_id=?";
	    $result = DbAuth::getObjects($sql, array($oldAccountId));

	    foreach ($result as $userGame) {
		$this->clearCachedToken($userGame['game'], $loginType, $username);
	    }
	} catch (Exception $e) {
	    error_log($e->getMessage());
	    $responseJson = json_encode($response);
	    echo $responseJson;
	    $this->haltProperly();
	}
	$response->ok = true;
	$response->message = "Username <strong>$username</strong> now logs into account ID <strong>$newAccountId</strong>";
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function getLoginsLikeUsername() {
	$response = new stdClass();
	$response->ok = false;
	
	$this->isAdmin($response, $this->gameId);

	$token = $this->reqParam('token');

	$tokenSafe = addslashes($token);

	$sql = "SELECT account_id FROM logins WHERE username LIKE '$tokenSafe%'";
	$results = DbAuth::getObjects($sql);

	$accountIds = array();
	foreach ($results as $row) {
	    $accountIds[] = $row['account_id'];
	}

	$sql = "SELECT user_game_id FROM user_games WHERE account_id IN  ('" . implode("','", $accountIds) . "') AND game=?";
	$sqlArgs = array($this->gameId);
	$results = DbAuth::getObjects($sql, $sqlArgs);

	$resultUserGameIds = array();

	foreach ($results as $result) {
	    $resultUserGameIds[] = $result['user_game_id'];
	}

	$response->ok = true;
	$response->user_game_ids = json_encode($resultUserGameIds);
	$responseJson = json_encode($response);
	echo $responseJson;
    }

    public function getIpsByUserGameId() {
	$response = new stdClass();
	$response->result = false;

	$this->canManageAccounts($response);

	$userGameId = $this->reqParam('user_game_id');

	$sql = "SELECT ip_address, event_date FROM user_ips WHERE user_game_id=?";
	$sqlArgs = array($userGameId);
	$result = DbAuth::getObjects($sql, $sqlArgs);

	$ips = array();
	if (count($result) > 0) {
	    foreach ($result as $row) {
		$ips[] = $row;
	    }
	}

	$response->result = true;
	$response->ips = $ips;


	$responseJson = json_encode($response);

	echo $responseJson;
    }

    public function getUsernameByUgids() {
	$response = new stdClass();
	$response->result = false;

	$this->canManageAccounts($response);

	$userGameIdString = urldecode($this->reqParam('user_game_ids'));
	$userGameIds = explode(',', $userGameIdString);
	
	$where = array();
	foreach($userGameIds as $ignoreme){
	    $where[] = '?';
	}
	$whereString = implode(',', $where);
	
	$sql = "SELECT user_game_id, username FROM logins 
		    INNER JOIN user_games ON logins.account_id = user_games.account_id
		WHERE login_type='email' AND user_games.user_game_id IN ($whereString)";
	
	$result = DbAuth::getObjects($sql, $userGameIds);

	$users = array();
	if (count($result) > 0) {
	    foreach ($result as $row) {
		$users[] = $row;
	    }
	}

	$response->result = true;
	$response->users = $users;

	$responseJson = json_encode($response);

	echo $responseJson;
    }
    
    public function getUserGameIdsByIp() {
	$response = new stdClass();
	$response->result = false;

	$this->canManageAccounts($response);

	// search user_ips table by ip_address
	$ip_address = urldecode($this->reqParam('ip_address'));
	$limit = urldecode($this->reqParam('limit'));
	$sql = "SELECT user_game_id, event_date FROM user_ips WHERE ip_address=? LIMIT ?";
	$sqlArgs = array($ip_address, $limit);
	$results = DbAuth::getObjects($sql, $sqlArgs);

	$response->num = count($results);

	// construct list of user_game_ids
	$resultUserGameIds = array();
	if (count($results) > 0) {
	    $response->result = true;
	    foreach ($results as $row) {
		$resultUserGameIds[] = $row['user_game_id'];
	    }
	}

	$response->user_game_ids = json_encode($resultUserGameIds);

	// send json encoded response
	echo json_encode($response);
    }

    public function verifyEmail() {
	$response = new stdClass();
	$response->ok = false;
	
	$this->isAdmin($response, $this->gameId);

	$id = $this->reqParam('id');

	$sql = "UPDATE logins SET verified=1 WHERE id=?";
	$sqlArgs = array($id);
	DbAuth::query($sql, $sqlArgs);
	
	$response->ok = true;
	echo json_encode($response);
    }

    private function logPermissionChange($isAdd, $targetAccountId, $sourceAccountId, $gamePermissionId) {
	// Determine the permission name right now (and game it applies to)
	$sql = 'SELECT * FROM game_permissions WHERE game_permission_id=?';
	$sqlArgs = array($gamePermissionId);
	$result = DbAuth::getObject($sql, $sqlArgs);
	$gameId = $result['game'];
	$permissionName = $result['name'];

	$sql = 'INSERT INTO account_game_permissions_log 
			( target_account_id, source_account_id, game_permission_id, game_permission_name, game_permission_game, action ) 
			VALUES ( ?, ?, ?, ?, ?, ? )';
	$sqlArgs = array($targetAccountId, $sourceAccountId, $gamePermissionId, $permissionName, $gameId, $isAdd ? 'add' : 'remove');
	DbAuth::query($sql, $sqlArgs);
    }

    public function isAdmin($response, $game_id, $exitOnFail = true) {
	$globalAdmin = $this->hasPermission($response, 'admin', null, false);
	if ($globalAdmin == null) {
	    $gameAdmin = $this->hasPermission($response, 'admin', $game_id, $exitOnFail);
	    return $gameAdmin;
	} else {
	    return $globalAdmin;
	}
    }

    public function getUserPermissions() {
	$response = new stdClass();
	$response->result = false;

	$game_id = intval($this->reqParam('game'));

	// If setting a permission they need to have admin priviledge on that game (or be global admin)
	$this->isAdmin($response, $game_id);

	$response->result = true;

	$response->game = new stdClass();
	$response->game->id = $game_id == null ? 0 : $game_id;
	$gameSettings = getGameSettings($game_id);
	$response->game->name = $game_id == null ? 'Auth' : ( isset($gameSettings['game_name']) ? $gameSettings['game_name'] : "Missing Name (${game_id})" );

	// Get a list of all available permissions for this game
	{
	    $sql = 'SELECT * FROM game_permissions WHERE ';
	    if ($game_id == null)
		$sql .= 'game IS NULL';
	    else
		$sql .= 'game=?';
	    $sqlArgs = $game_id == null ? null : array($game_id);
	    $results = DbAuth::getObjects($sql, $sqlArgs);

	    $response->permissions = $results;
	}

	// Get a list of all the current users with permissions for this game (and their permissions)
	{
	    $sql = "SELECT logins.account_id, username, account_game_permissions.game_permission_id FROM account_game_permissions, logins, game_permissions
			WHERE account_game_permissions.account_id=logins.account_id 
			AND game_permissions.game_permission_id=account_game_permissions.game_permission_id
			AND login_type='email' ";
	    if ($game_id == null)
		$sql .= 'AND game_permissions.game IS NULL';
	    else
		$sql .= 'AND game_permissions.game=?';
	    $sqlArgs = $game_id == null ? null : array($game_id);
	    $results = DbAuth::getObjects($sql, $sqlArgs);

	    $perUserPemissions = new stdClass();
	    foreach ($results as $permission) {
		$thisUser = null;
		if (!property_exists($perUserPemissions, $permission['account_id'])) {
		    $perUserPemissions->{$permission['account_id']} = $thisUser = new stdClass();
		    $thisUser->account_id = $permission['account_id'];
		    $thisUser->username = $permission['username'];
		    $thisUser->permissions = array();
		} else {
		    $thisUser = $perUserPemissions->{$permission['account_id']};
		}

		array_push($thisUser->permissions, $permission['game_permission_id']);
	    }
	    $perUserPemissionsArray = array();
	    foreach ($perUserPemissions as $key => $value)
		array_push($perUserPemissionsArray, $value);

	    $response->users = $perUserPemissionsArray;
	}

	echo json_encode($response);
    }

    public function setUserPermissions() {
	$response = new stdClass();
	$response->result = false;

	if ($this->hasParam('account')) {
	    $account_id = $this->reqParam('account');
	} else {
	    $username = $this->reqParam('username');

	    $sql = 'SELECT account_id FROM logins WHERE username=?';
	    $sqlArgs = array($username);
	    $result = DbAuth::getObject($sql, $sqlArgs);

	    if ($result == null) {
		$response->message = "User not found";
		$this->haltProperly(json_encode($response));
	    }

	    $account_id = $result['account_id'];
	}

	$game_id = intval($this->reqParam('game'));
	$permission = intval($this->reqParam('permission'));
	$delete = $this->hasParam('delete');

	// If setting a permission they need to have admin priviledge on that game (or be global admin)
	$adminId = $this->isAdmin($response, $game_id);

	// TODO: Sanity check the permission being added exists for that game
	if ($delete) {
	    $sql = 'DELETE FROM account_game_permissions WHERE account_id=? And game_permission_id=?';
	    $sqlArgs = array($account_id, $permission);
	    DbAuth::query($sql, $sqlArgs);

	    $this->logPermissionChange(false, $account_id, $adminId, $permission);
	} else {
	    try {
		$sql = 'INSERT INTO account_game_permissions ( account_id, game_permission_id ) VALUES ( ?, ? )';
		$sqlArgs = array($account_id, $permission);
		DbAuth::query($sql, $sqlArgs);

		$this->logPermissionChange(true, $account_id, $adminId, $permission);
		$response->result = true;
	    } catch (Exception $e) {
		$response->message = $e->getMessage();
	    }
	}

	echo json_encode($response);
    }

    public function createPermissions() {
	$game_id = intval($this->reqParam('game'));
	$permission = $this->reqParam('permission');

	$response = new stdClass();
	$response->result = false;

	// If setting a permission they need to have admin priviledge on that game (or be global admin)
	$this->isAdmin($response, $game_id);

	try {
	    $sql = 'INSERT INTO game_permissions ( game, name ) VALUES ( ?, ? )';
	    $sqlArgs = array($game_id, $permission);
	    $result = DbAuth::query($sql, $sqlArgs);

	    $response->permission = new stdClass();
	    $response->permission->game_permission_id = $result->insert_id;
	    $response->permission->game = $game_id;
	    $response->permission->name = $permission;

	    $response->result = true;
	} catch (Exception $e) {
	    $response->message = $e->getMessage();
	}

	echo json_encode($response);
    }

    public function deletePermissions() {
	$game_id = intval($this->reqParam('game'));
	$permission = intval($this->reqParam('permission'));

	$response = new stdClass();
	$response->result = false;

	// If setting a permission they need to have admin priviledge on that game (or be global admin)
	$this->isAdmin($response, $game_id);

	try {
	    $sql = 'DELETE FROM game_permissions WHERE game_permission_id=?';
	    $sqlArgs = array($permission);
	    $result = DbAuth::query($sql, $sqlArgs);
	    $response->result = true;
	} catch (Exception $e) {
	    $response->message = $e->getMessage();
	}

	echo json_encode($response);
    }

    public function renamePermissions() {
	$game_id = intval($this->reqParam('game'));
	$permission = intval($this->reqParam('permission'));
	$name = $this->reqParam('name');

	$response = new stdClass();
	$response->result = false;

	// If setting a permission they need to have admin priviledge on that game (or be global admin)
	$this->isAdmin($response, $game_id);

	try {
	    $sql = 'UPDATE game_permissions SET name=? WHERE game_permission_id=?';
	    $sqlArgs = array($name, $permission);
	    $result = DbAuth::query($sql, $sqlArgs);
	    $response->result = true;
	} catch (Exception $e) {
	    $response->message = $e->getMessage();
	}

	echo json_encode($response);
    }

    public function showDecryptedToken() {
	$response = new stdClass();
	$response->result = false;

	$encryptedToken = $this->reqParam('token');

	$this->isAdmin($response, $this->gameId);
	$decryptedToken = $this->getDecryptedToken($encryptedToken);

	if ($decryptedToken[0] == '{')
	    $response->token = $decryptedToken;
	else
	    $response->token = '{}';

	echo json_encode($response);
    }

}
