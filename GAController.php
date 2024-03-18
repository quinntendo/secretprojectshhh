<?php
class GAController extends ControllerBase {

    const ACHIEVEMENT_NAME = 'a';
    const USER_GAME_ID = 'ugid';

    protected $userGameId;
    protected $encryptedToken;
    protected $decryptedToken;
    protected $token;
    protected $language;

    public function init() {
	$this->gameId = $this->reqParam(self::GAME_ID);
	$this->userGameId = $this->reqParam(self::USER_GAME_ID);
	$this->language = $this->hasParam('language') ? $this->reqParam('language') : 'en';
	$this->encryptedToken = $this->getEncryptedToken();
	$this->decryptedtoken = $this->getDecryptedToken($this->encryptedToken);
	$this->token = $this->getDecodedToken($this->decryptedtoken);
    }

    public function getAchievements() {
	$this->requireClientToken();
    }

    public function giveAchievement() {
	$this->requireServerToken();
	$achievementName = $this->reqParam(self::ACHIEVEMENT_NAME);

	try {

	    $sql = "SELECT * FROM ga_achievements WHERE game=? AND name=?";
	    $achievement = DbAuth::getObject($sql, array($this->gameId, $achievementName));
	    if (!$achievement) {
		error_log("Achievement not found");
		$this->haltProperly('{"result":"false", "status":"Unknown achievement"}');
	    }

	    $achievementId = $achievement['id'];
	    $rewards = json_decode($achievement['rewards']);

	    $sql = "SELECT * FROM user_achievements WHERE game=? AND achievement=? AND user_game_id=?";
	    if (!DbAuth::getObject($sql, array($this->gameId, $achievementId, $this->userGameId))) {
		$sql = "INSERT INTO user_achievements SET game=?, achievement=?, user_game_id=?, earned_on=NOW()";
		DbAuth::query($sql, array($this->gameId, $achievementId, $this->userGameId));

		// need to tell the 'other' game about the reward
		foreach ($rewards as $target => $reward) {
		    $rewardJson = json_encode($reward);
		    $responseAddress = GlobalAchievementSettings::get("GAME_RESPONSE_URL_" . strtoupper($target));
		    $responseArguments = GlobalAchievementSettings::get("GAME_RESPONSE_ARG_" . strtoupper($target)) . '=' . $rewardJson . '&ugid=' . $this->userGameId;


		    error_log("Sending: " . $responseArguments);

		    $headers = [
			'Accept: application/json',
			'Cache-Control: no-cache',
			'Content-Type: application/x-www-form-urlencoded; charset=utf-8',
			"Authorization: Bearer " . $this->encryptedToken
		    ];

		    $ch = curl_init($responseAddress);
		    curl_setopt($ch, CURLOPT_POST, 1);
		    curl_setopt($ch, CURLOPT_POSTFIELDS, $responseArguments);
		    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
		    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		    if (substr($responseAddress, 0, 5) == 'https') {
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
		    }
		    $response = curl_exec($ch);
		    error_log(print_r($response, true));
		}

		echo '{"result":"true"}';
	    } else {
		echo '{"result":"false", "status":"Already earned"}';
	    }
	} catch (Exception $e) {
	    if (isSlimException($e))
		return;

	    echo '{"result":"false", "status":"Unknown"}';
	}
    }

}
