<?php

class FacebookMigrationController extends ControllerBase
{
	const ACCESS_KEY = 'b501e78b-fc01-4b56-9d62-46c94a080a05';
	const LOGIN_TYPE = 'fb';
	//const DATE_ALLOWED = '2016-03-13 00:00:00';
	const DATE_ALLOWED = '2023-03-13 11:00:00';	
	const MAX_DEVICES = 5;
	
	public function swapFBAccount()
	{
		$accessKey = $this->reqParam("access_key");
		$guestUserGameId = $this->reqParam("guest_id");
		$fbUserGameId = $this->reqParam("fb_id");
		
		try
		{
			if ($accessKey != FacebookMigrationController::ACCESS_KEY)
				throw new Exception("Invalid access key");
			
			// do the exact same lookup as before for validation
			$recoveryAccounts = $this->findRecoveryAccounts($guestUserGameId);
			
			// fbUserGameId should be in recoveryAccounts list
			$accountFound = false;
			foreach ($recoveryAccounts as $account) {
				if ($account['user_game_id'] == $fbUserGameId) {
					$accountFound = true;
					break;
				}
			}
			if (!$accountFound)
				throw new Exception("Unable to find recovery FB user_game_id '{$fbUserGameId}' for user_game_id '{$userGameId}'");
			
			// actually do the swap
			$this->swapAccounts($guestUserGameId, $fbUserGameId);
			
			$res = new stdClass();
			$res->ok = true;
			$res->account = $fbUserGameId;

			$json = json_encode($res);
			echo $json;
		}
		catch (Exception $e)
		{
			sendErrorMessage(ResponseCode::GENERAL_ERROR, $e->getMessage());
		}
		
		$this->haltProperly();
	}
	
	public function findFBAccount()
	{
		$accessKey = $this->reqParam("access_key");
		$guestUserGameId = $this->reqParam("guest_id");
		
		try
		{
			if ($accessKey != FacebookMigrationController::ACCESS_KEY)
				throw new Exception("Invalid access key");
			
			$recoveryAccounts = $this->findRecoveryAccounts($guestUserGameId);
			
			//error_log("Found " . count($recoveryAccounts) . " accounts that could potentially match");		
			//$jsonResults = json_encode($recoveryAccounts);
			//error_log("Accounts are: " . $jsonResults);
			
			$res = new stdClass();
			$res->ok = true;
			$res->accounts = $recoveryAccounts;

			$json = json_encode($res);
			echo $json;
		}
		catch (Exception $e)
		{
			//error_log("Error during findFBAccount: " . $e->getMessage());
			sendErrorMessage(ResponseCode::GENERAL_ERROR, $e->getMessage());
		}
		
		$this->haltProperly();
	}
	
	private function swapAccounts($oldUserGameId, $newUserGameId)
	{		
		if ($oldUserGameId == $newUserGameId)
			throw new Exception("Matching user_game_ids for swap");
		
		$oldAccountId = $this->getAccountId($oldUserGameId, 1);
		$newAccountId = $this->getAccountId($newUserGameId, 1);
		
		// log our intention
		$sql = "INSERT INTO `account_fb_swaps` SET `old_user_game_id` = ?, `new_user_game_id` = ?, `old_account_id` = ?, `new_account_id` = ?";
		$sqlArgs = array($oldUserGameId, $newUserGameId, $oldAccountId, $newAccountId);
		if (!DbAuth::query($sql, $sqlArgs))
			throw new Exception("Unable to log swap intention for user_game_id '{$oldUserGameId}'");
		
		// THIS IS THE ONE!!!
		$sql = "UPDATE `logins` SET `account_id` = ? WHERE `account_id` = ?";
		$sqlArgs = array($newAccountId, $oldAccountId);
		if (!DbAuth::query($sql, $sqlArgs))
			throw new Exception("Unable to swap accounts for user_game_id '{$oldUserGameId}' from '{$oldAccountId}' to '{$newAccountId}'");
	}
	
	private function getAccountId($userGameId, $game)
	{
		if (empty($userGameId))
			throw new Exception("Can't lookup empty user_game_id");
			
		$sql = "SELECT `account_id` FROM `user_games` WHERE `user_game_id` = ? AND `game` = ?";
		$sqlArgs = array($userGameId, $game);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		if (!$results || count($results) != 1)
			throw new Exception("Can't find account_id for user_game_id '{$userGameId}'");
		
		return $results[0]['account_id'];
	}
	
	private function findRecoveryAccounts($guestUserGameId)
	{
		$guestAccountId = $this->getGuestAccountId($guestUserGameId);
		$guestDeviceIds = $this->getGuestDevices($guestUserGameId);
		$guestIps = $this->getGuestIps($guestUserGameId);
		//$guestIps = $this->getGuestIps('5m73g679fw');
			
		return $this->getFacebookAccount($guestUserGameId, $guestDeviceIds, $guestIps);	
	}
	
	private function getGuestAccountId($userGameId)
	{
		$sql = "SELECT * FROM `user_games` WHERE `account_id` IN (SELECT `account_id` FROM `user_games` WHERE `user_game_id` = ?)";
		$sqlArgs = array($userGameId);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		// check that accounts only played 1 game
		if (count($results) == 0)
			throw new Exception("No games for user_game_id '{$userGameId}'");
		
		if (count($results) > 1)
			throw new Exception("Invalid number of games for user_game_id '{$userGameId}'");
		
		// and that game is msm
		$game = $results[0]['game'];
		if ($game != 1)
			throw new Exception("Invalid game '{$game}' for user_game_id '{$userGameId}'");
		
		// check date created of account
		//$dateCreated = $results[0]['date_created'];
		//if ($dateCreated < FacebookMigrationController::DATE_ALLOWED)
		//	throw new Exception("Invalid creation date '{$dateCreated}' for user_game_id '{$userGameId}'");
		
		$guestAccountId = $results[0]['account_id'];
		
		// retrieve login info
		$sql = "SELECT * FROM `logins` WHERE `account_id` = ?";
		$sqlArgs = array($guestAccountId);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		// must have at least 1 valid login
		if (count($results) == 0)
			throw new Exception("No login info for user_game_id '{$userGameId}'");
		
		// ensure no logins of type already bound
		$invalidLoginType = FacebookMigrationController::LOGIN_TYPE;
		foreach ($results as $guestAccount) {	
			if ($guestAccount['login_type'] == $invalidLoginType)
				throw new Exception("Login of type '{$invalidLoginType}' already bound for user_game_id '{$userGameId}'");
		}
		
		// now we know $userGameId is a candidate for rebinding to a found facebook	
		return $guestAccountId;
	}
	
	private function getGuestDevices($userGameId)
	{
		$sql = "SELECT * FROM `user_game_devices` WHERE `user_game_id` = ?";
		$sqlArgs = array($userGameId);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		//error_log("Found devices: " . json_encode($results));
		
		// check that accounts that have played on no devices (wtf)
		if (count($results) == 0)
			throw new Exception("No devices for user_game_id '{$userGameId}'");
		
		// check for accounts that have played on too many devices
		if (count($results) > FacebookMigrationController::MAX_DEVICES)
			throw new Exception("Invalid number of devices (" . count($results) . ") for user_game_id '{$userGameId}'");
		
		// ugh, just redo the query to find all devices with device_id that match
		// exclude empty devices ids and ones starting with '00000000' or 'FUCK'
		$sql = "SELECT * FROM `user_game_devices` WHERE `device_fk` IN (SELECT `id` AS `device_fk` FROM `devices` WHERE `device_id` IN (select DISTINCT(`device_id`) FROM `devices` WHERE `id` IN (SELECT `device_fk` FROM `user_game_devices` WHERE `user_game_id` = ?)) AND `device_id` != '' AND `device_id` NOT LIKE '00000000%' AND `device_id` NOT LIKE 'FUCK%')";
		$sqlArgs = array($userGameId);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		// check that accounts that have played on no devices (wtf)
		if (count($results) == 0)
			throw new Exception("No valid devices for user_game_id '{$userGameId}'");
		
		$deviceFKs = array();
		foreach ($results as $device)
			$deviceFKs[] = $device['device_fk'];

		//error_log("Found potential devices: " . json_encode($deviceFKs));
		
		// now we know these devices are a candidate for searching for facebook accounts
		return $deviceFKs;
	}
	
	private function getGuestIps($userGameId)
	{
		$sql = "SELECT `ip_address` FROM `user_ips` WHERE `user_game_id` = ?";
		$sqlArgs = array($userGameId);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		// ensure they have at least one ip
		if (count($results) == 0)
			throw new Exception("No ips found for user_game_id '{$userGameId}'");
		
		// construct list of ips for use in searching
		$ips = array();
		foreach ($results as $userIp)
		{
			$ipAddress = $userIp['ip_address'];
			
			// filter out ipv6 addresses and malformed ipv4 ones
			if (!strpos($ipAddress, ':') && substr_count($ipAddress, '.') == 3) {
				// strip off last octal and replace with '%'
				$ips[] = substr($ipAddress, 0, strrpos($ipAddress, '.')+1) . '%';
			}
		}
		
		// ensure we found at least 1 valid ip
		if (count($ips) == 0)
			throw new Exception("No valid ips found for user_game_id '{$userGameId}'");
		
		/*
		$testArgs = array(1234, 'xyz', 1, 'fb', '2023-03-13 00:00:00');
		$foo = array_merge($testArgs, $ips);
		
		$blah = print_r($foo, true);
		error_log("Array is " . str_replace("\n", "", $blah));
		*/
		
		return $ips;
	}
	
	private function getFacebookAccount($guestGameId, $guestDeviceIds, $guestIps)
	{
		$loginType = FacebookMigrationController::LOGIN_TYPE;
		$lastPlayed = FacebookMigrationController::DATE_ALLOWED;
		
		// device id parameters
		$sqlDevices = "(";
		foreach ($guestDeviceIds as $id) {
			$sqlDevices .= "?";
			if (next($guestDeviceIds))
				$sqlDevices .= ", ";
		}
		$sqlDevices .= ")";
		
		// this is the one ... that finds potential fb accounts
		//$sql = "SELECT `login_type`, `user_games`.`account_id`, `user_games`.`user_game_id`, `last_played`, `user_ips`.`ip_address` " .
		$sql = "SELECT `user_games`.`account_id`, `user_games`.`user_game_id` " .
			"FROM `user_game_devices` " .
			"INNER JOIN `user_games` ON `user_game_devices`.`user_game_id` = `user_games`.`user_game_id` " .
			"INNER JOIN `logins` ON `user_games`.`account_id` = `logins`.`account_id` " .
			"INNER JOIN `user_ips` ON `user_games`.`user_game_id` = `user_ips`.`user_game_id` " .
			"WHERE `device_fk` IN " . $sqlDevices . " AND `user_game_devices`.`user_game_id` != ? " .
			"AND `game` = ? AND `login_type` = ? and `last_played` < ?";
		$sqlArgs = array_merge($guestDeviceIds, array($guestGameId, 1, $loginType, $lastPlayed));
		
		// add in ip address like matching
		$sql2 = "";
		if (count($guestIps) > 0)
		{
			$sql2 .= " AND (";
			foreach ($guestIps as $ip) {
				$sql2 .= "`user_ips`.`ip_address` LIKE ?";
				if (next($guestIps))
					$sql2 .= " OR ";
			}
			$sql2 .= ")";
		}
		
		$sql .= $sql2 . " GROUP BY `account_id`";
		$sqlArgs = array_merge($sqlArgs, $guestIps);
		$results = DbAuth::getObjects($sql, $sqlArgs);
		
		// must be at least 1 user who played on this device who is not the guest
		if (count($results) == 0)
			throw new Exception("No valid fb users found who played on device used by user_game_id '{$guestGameId}'");
		
		return $results;
	}
	
}
