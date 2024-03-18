<?php

class UserGameConsent {

    var $consent;
    var $accountId;
    var $gameId;

    function __construct($gameId, $accountId) {
	$this->accountId = $accountId;
	$this->gameId = $gameId;

	$sql = 'SELECT consent FROM user_game_consents WHERE account_id=? AND game=?';
	$sqlArgs = array($accountId, $gameId);
	$result = DbAuth::getObject($sql, $sqlArgs);

	if (!is_null($result)) {
	    $consentJson = $result['consent'];
	    $this->consent = json_decode($consentJson);
	}
    }

    static function doesGameRequireConsent($gameId, $consentSetting) {
	$gameSettings = getGameSettings($gameId);
	if (array_key_exists($consentSetting, $gameSettings) && !is_null($gameSettings[$consentSetting])) {
	    return true;
	}
	return false;
    }

    function requiresConsent($consentSetting) {
	if (self::doesGameRequireConsent($this->gameId, $consentSetting)) {
	    if (isset($this->consent->$consentSetting)) {
		$dateOfConsent = $this->consent->$consentSetting->date;
		$gameSettings = getGameSettings($this->gameId);
		$consent_last_update = $gameSettings[$consentSetting];
		if ($dateOfConsent >= $consent_last_update) {
		    return false;
		}
	    }
	    return true;
	} else {
	    //error_log("consent setting not found in game setting " . $consentSetting);
	}
	return false;
    }

    function updateConsents($consentList) {
	foreach ($consentList as $consent)
	    $this->updateConsent($consent);
    }

    function updateConsent($consentSetting) {

	$existingConsent = !is_null($this->consent);
	if (!$existingConsent) {
	    $this->consent = new stdClass();
	}

	if (!isset($this->consent->$consentSetting)) {
	    $this->consent->$consentSetting = new stdClass();
	}

	$this->consent->$consentSetting->date = time();
	$json = json_encode($this->consent);

	try {
	    if (!$existingConsent) {
		$sql = "INSERT INTO user_game_consents SET consent=?, account_id=?, game=?";
	    } else {
		$sql = 'UPDATE user_game_consents SET consent=? WHERE account_id=? AND game=?';
	    }
	    $sqlArgs = array($json, $this->accountId, $this->gameId);
	    DbAuth::query($sql, $sqlArgs);
	} catch (Exception $e) {
	    if (isSlimException($e))
		return;

	    error_log($e->getMessage());
	}
    }

    function updateAccountId($accountId) {

	$existingConsent = !is_null($this->consent);
	if ($existingConsent) {
	    try {
		$sql = 'UPDATE user_game_consents SET account_id=? WHERE account_id=? AND game=?';
		$sqlArgs = array($accountId, $this->accountId, $this->gameId);
		DbAuth::query($sql, $sqlArgs);
		$this->accountId = $accountId;
	    } catch (Exception $e) {
		if (isSlimException($e))
		    return;

		error_log($e->getMessage());
	    }
	}
    }

}

?>