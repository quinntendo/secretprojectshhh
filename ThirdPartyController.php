<?php

class ThirdPartyController extends ControllerBase {

    use Authentication;

    public function init() {
	$this->gameId = $this->reqParam(parent::GAME_ID);

	$this->encryptedToken = $this->getEncryptedToken();
	$this->decryptedtoken = $this->getDecryptedToken($this->encryptedToken);
	$this->token = $this->getDecodedToken($this->decryptedtoken);
    }

    public function isEmailBlacklisted() {
	$this->requireServerToken();

	$emailAddress = $this->reqParam(self::EMAIL_ADDRESS);

	if (!filter_var($emailAddress, FILTER_VALIDATE_EMAIL)) {
	    sendErrorMessage(ResponseCode::ERROR_BAD_EMAIL_ADDRESS);
	    $this->haltProperly();
	}

	// check if user email is banned
	$emailBlacklisted = isEmailBanned($emailAddress);

	$res = new stdClass();
	$res->ok = true;
	$res->email_blacklisted = $emailBlacklisted;

	$json = json_encode($res);
	echo $json;
	$this->haltProperly();
    }

}
