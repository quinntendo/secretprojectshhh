<?php

/* TODO: move all these functions to proper class locations. */


/* * ***************** AUTH FUNCTIONS **************************** */

define('BOUNCE_TRIGGER', 4);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require(LIB_DIR . '/PHPMailer/src/Exception.php');
require(LIB_DIR . '/PHPMailer/src/PHPMailer.php');
require(LIB_DIR . '/PHPMailer/src/SMTP.php');

/* * *** NEW **** */

use GeoIp2\Database\Reader;
use Aws\Ses\SesClient;

function createToken($accountId, $userGameIdArray, $gameId, $permissionsArray, $username, $loginType) {

    $gameSettings = getGameSettings($gameId);

    // accountid, game, generated_on, expires_at
    $tokenObj = new stdClass();
    $tokenObj->account_id = $accountId;
    $tokenObj->user_game_ids = $userGameIdArray;
    $tokenObj->game = $gameId;
    $tokenObj->token_version = 1;
    $tokenObj->generated_on = time();
    $tokenObj->expires_at = $tokenObj->generated_on + $gameSettings['token_expires_after'];
    $tokenObj->username = $username;
    $tokenObj->login_type = $loginType;

    if (!is_null($permissionsArray)){
	$tokenObj->permissions = $permissionsArray;
	
	// extend the token lifetime for non is_server permissions (admin accounts)
	if(!property_exists($permissionsArray, 'is_server'))
	    $tokenObj->expires_at = $tokenObj->generated_on + $gameSettings['admin_token_expires_after'];
    }

    $tokenJson = json_encode($tokenObj);
    return $tokenJson;
}

function createRefreshToken($accountId, $userGameIdArray, $gameId, $username, $loginType, $deviceId, $advertiserId) {

    $guid = generateGUID();

    $sql = "SELECT * FROM devices WHERE device_id=? AND advertiser_id=?";
    $args = array($deviceId, $advertiserId);
    $device = DbAuth::getObject($sql, $args);
    $deviceFk = is_null($device) ? NULL : $device['id'];

    $sql = "SELECT * FROM user_games WHERE user_game_id=? AND game=?";
    $args = array($userGameIdArray[0], $gameId);
    $result = DbAuth::getObject($sql, $args);

    $userGamesFk = $result['id']; //TODO: error if null

    $gameSettings = getGameSettings($gameId);
    $time = time();
    $expiryTime = $time + $gameSettings['refresh_token_expires_after'];

    if (DbAuth::objectExists("SELECT * FROM refresh_tokens WHERE user_games_fk=? AND devices_fk=?", array($userGamesFk, $deviceFk))) {
	$sql = 'UPDATE refresh_tokens SET refresh_token=?, generated_on=FROM_UNIXTIME(?), expires_at=FROM_UNIXTIME(?) WHERE user_games_fk=? AND devices_fk=?';
	$args = array($guid, $time, $expiryTime, $userGamesFk, $deviceFk);
	DbAuth::query($sql, $args);
    } else {
	$sql = "INSERT INTO refresh_tokens SET user_games_fk=?, devices_fk=?, refresh_token=?, generated_on=FROM_UNIXTIME(?), expires_at=FROM_UNIXTIME(?)";
	$args = array($userGamesFk, $deviceFk, $guid, $time, $expiryTime);
	DbAuth::query($sql, $args);
    }

    // accountid, game, generated_on, expires_at
    $tokenObj = new stdClass();
    $tokenObj->account_id = $accountId;
    $tokenObj->user_game_ids = $userGameIdArray;
    $tokenObj->game = $gameId;
    $tokenObj->token_version = 1;
    $tokenObj->generated_on = $time;
    $tokenObj->expires_at = $expiryTime;
    $tokenObj->username = $username;
    $tokenObj->login_type = $loginType;
    $tokenObj->guid = $guid;

    $tokenJson = json_encode($tokenObj);

    return Encryption::encrypt($tokenJson, $gameSettings['refresh_token_encryption_vector'], $gameSettings['refresh_token_encryption_secret']);
}

function generateGUID() {

    $data = openssl_random_pseudo_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);    // set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);    // set bits 6-7 to 10
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function getGameData($gameId) {
    $result = CacheWrapper::get("game_data_{$gameId}");
    if (empty($result)) {

	$sql = "SELECT * FROM games WHERE id=?";
	$args = array($gameId);
	$result = DbAuth::getObject($sql, $args);

	if (!is_null($result)) {
	    CacheWrapper::set("game_data_{$gameId}", $result, CacheWrapper::TIMEOUT_FIVE_MINUTES);
	}
    }

    return $result;
}

function getGameSettings($gameId) {
    $settings = CacheWrapper::get("game_game_settings_{$gameId}");
    if (empty($settings)) {
	$sql = "SELECT gs.setting, (CASE WHEN ggs.value IS NOT NULL THEN ggs.value ELSE gs.default END)AS 'value' FROM game_game_settings AS ggs 
		RIGHT JOIN game_settings AS gs ON gs.id=ggs.setting WHERE game=? OR (gs.default IS NOT NULL AND ggs.value IS NULL);";
	$args = array($gameId);

	$settings = array();
	$result = DbAuth::getObjects($sql, $args);
	if (!is_null($result)) {
	    foreach ($result as $row) {
		$settings[$row['setting']] = $row['value'];
	    }
	    CacheWrapper::set("game_game_settings_{$gameId}", $settings, CacheWrapper::TIMEOUT_FIVE_MINUTES);
	}
    }

    return $settings;
}

function getGameName($gameId) {
    if ($gameId == null)
	return 'Auth';

    $gameSettings = getGameSettings($game_id);
    $gameName = isset($gameSettings['game_name']) ? $gameSettings['game_name'] : "Missing Name (${game_id})";

    return $gameName;
}

/* * *** KEEP **** */

function sendErrorMessage($errorId, $messageOverride = null) {
    $res = new stdClass();
    $res->ok = false;
    $res->error = $errorId;
    if (is_null($messageOverride)) {
	$res->message = ResponseCode::getMessage($errorId);
    } else {
	$res->message = $messageOverride;
    }

    $json = json_encode($res, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    echo $json;
}

function sendOkMessage($data = null) {
    $res = new stdClass();
    $res->ok = true;

    if (!is_null($data)) {
	foreach ($data as $key => $value) {
	    if ($key !== 'ok')
		$res->$key = $value;
	}
    }

    $json = json_encode($res, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    echo $json;
}

function generateRandomString($length = 8) {
    $chars = "bcdfghjkmnpqrstvwxyz23456789";
    //srand((double) microtime() * 1000000);
    //mt_srand();
    $i = 1;
    $string = '';
    while ($i <= $length) {
	$num = mt_rand() % strlen($chars);
	$tmp = substr($chars, $num, 1);
	$string = $string . $tmp;
	$i++;
    }
    return $string;
}

function getRealIpAddr() {

    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
	return $_SERVER['HTTP_CLIENT_IP'];
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
	return $_SERVER['HTTP_X_FORWARDED_FOR'];
    }

    if (isset($_SERVER['REMOTE_ADDR'])) {
	return $_SERVER['REMOTE_ADDR'];
    }

    return '127.0.0.1';
}

function countryFromIP($ip) {

    // TODO: MAKE THIS SHIT WORK
    return 'CA';

    $reader = new Reader('GeoIP2-Country.mmdb');
    $reader->close();

    $record = $reader->country($ip);
    return $record->country->isoCode;
}

function sendVerificationEmail($accountId, $email, $language, $gameId, $gameName) {

    $hash = md5($email . '_' . HASH_SEED);

    $urlEncodedEmail = urlencode($email);

    $link = "https://" . HOSTNAME . INSTALL_PATH . "/verify.php?lang={$language}&a={$accountId}&e={$urlEncodedEmail}&h={$hash}";

    $preText = file_get_contents(TXT_DIR . "/{$language}/register.html");

    $body = str_replace("{VERIFICATION_URL}", $link, $preText);
    $subject = $gameName . " Email Confirmation";

    return sendEmailMessage($email, $subject, $body);
}


function sendPasswordRecoveryEmailForCET($email)
{
    $sql = "SELECT id, account_id, username, verified FROM logins WHERE username=? AND login_type='email'";
    $sqlArgs = array($email);
    $result = DbAuth::getObject($sql, $sqlArgs);
    if ($result) {

	$loginId = $result['id'];
	$accountId = $result['account_id'];
	$timestamp = time();

	$hash = md5(HASH_SEED . "{$accountId}_{$email}_{$timestamp}" . HASH_SEED);
	$link = "https://" . HOSTNAME . INSTALL_PATH . "/reset.php?l=$loginId&t=$timestamp&code=$hash&language=en";

	$body = "The Monster Handlers have sent you this password recovery email.<br><br> Please <a href=\"$link\">click here</a> to reset your password. <br> If you have any trouble clicking the above link please paste the link below into your browser: <br> $link";
	$subject = "Big Blue Bubble password recovery";

	return sendEmailMessage($email, $subject, $body, true);
    }

}

function sendEmailMessage($recipient, $subject, $body, $skipChecks=false) {

    if(!$skipChecks){
	if (isEmailBanned($recipient)) {
	    return false;
	}
    }
    
    //only check cache if the recipient is NOT a bbb address (don't enforce SES spam prevention for bbb users)
    if(strpos($recipient, '@bigbluebubble.com') === false || $skipChecks === false){
	$cacheKey = md5("SES-{$recipient}-{$subject}");
	if (CacheWrapper::get($cacheKey)) {
	    error_log("SES PREVENTION is working : {$recipient} '{$subject}'");
	    return true;
	}
    }

    if (USE_LOCAL_MAIL_SERVER) {

	$headers = 'MIME-Version: 1.0' . "\r\n";
	$headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
	$headers .= 'From: ' . WEBSITE_EMAIL_FROM . ' <' . WEBSITE_EMAIL_ADDY . '>' . "\r\n";
	$headers .= 'Reply-To: ' . WEBSITE_EMAIL_FROM . ' <' . WEBSITE_EMAIL_ADDY . '>' . "\r\n";

	ini_set("SMTP", "aspmx.l.google.com");
	ini_set("sendmail_from", WEBSITE_EMAIL_ADDY);

	try {
	    //error_log("$recipient, $subject, $body, $headers," . WEBSITE_EMAIL_ADDY);
	    $result = mail($recipient, $subject, $body, $headers, "-f " . WEBSITE_EMAIL_ADDY);
	} catch (Exception $e) {
	    return false;
	}

        if(strpos($recipient, '@bigbluebubble.com') === false){
	    CacheWrapper::set($cacheKey, 1, CacheWrapper::TIMEOUT_FIFTEEN_MINUTES);
	}
	return $result;
    } else {

	$client = SesClient::factory(array(
	    'region' => 'us-east-1',
	    'version' => '2010-12-01'
	));

	try {

	    $origErrorLog = ini_get("error_log");
	    ini_set("display_errors", 1);
	    ini_set("error_log", "/tmp/ses-response.log");

	    $result = $client->sendEmail(
		    array(
			// Source is required
			'Source' => WEBSITE_EMAIL_ADDY,
			// Destination is required
			'Destination' => array(
			    'ToAddresses' => array($recipient)
			),
			// Message is required
			'Message' => array(
			    // Subject is required
			    'Subject' => array(
				// Data is required
				'Data' => $subject
			    ),
			    // Body is required
			    'Body' => array(
				'Html' => array(
				    // Data is required
				    'Data' => $body
				)
			    )
			)
		    )
	    );

	    if (!$result) {
		error_log(" email fail ");
		ini_set("error_log", $origErrorLog); // temp
		return false;
	    }
	} catch (Exception $e) {
	    error_log(" email fail " . $e->getMessage());
	    ini_set("error_log", $origErrorLog); // temp
	    return false;
	}

	ini_set("error_log", $origErrorLog); // temp

	if(strpos($recipient, '@bigbluebubble.com') === false || $skipChecks === false){
	    CacheWrapper::set($cacheKey, 1, CacheWrapper::TIMEOUT_FIFTEEN_MINUTES);
	}
	return true;
    }
}

// Not doing any ban or cache checking
function sendEmailComplex(
	$fromName,
	$toList,
	$bccList,
	$replyToList,
	$subject,
	$messageHTML,
	$messageTEXT,
	$attachmentList
) {
    $mail = new PHPMailer(true);
    $mail->CharSet = 'UTF-8';
    $mail->setFrom(WEBSITE_EMAIL_ADDY, $fromName);

    if ($toList != null) {
	foreach ($toList as $to)
	    $mail->addAddress($to['email'], array_key_exists('name', $to) ? $to['name'] : '' );
    }

    if ($bccList != null) {
	foreach ($bccList as $bcc)
	    $mail->addBCC($bcc['email'], array_key_exists('name', $bcc) ? $bcc['name'] : '' );
    }

    if ($replyToList != null) {
	foreach ($replyToList as $replyTo)
	    $mail->addReplyTo($replyTo['email'], array_key_exists('name', $replyTo) ? $replyTo['name'] : '' );
    }

    $mail->Subject = $subject;

    if ($messageHTML != null) {
	$mail->isHTML(true);
	$mail->Body = $messageHTML;

	if ($messageTEXT != null)
	    $mail->AltBody = $messageTEXT;
    } else if ($messageTEXT != null) {
	$mail->isHTML(false);
	$mail->Body = $messageTEXT;
    } else {
	$mail->isHTML(false);
	$mail->Body = '';
    }

    if ($attachmentList != null) {
	foreach ($attachmentList as $key => $value)
	    $mail->addStringAttachment($value, $key);
    }

    if (USE_LOCAL_MAIL_SERVER) {
	$mail->isSMTP();
	//print( $mail->createHeader() . "\n" . $mail->createBody() );

	$mail->Host = 'aspmx.l.google.com';

	try {
	    $mail->send();
	} catch (Exception $e) {
	    error_log('Message could not be sent. Mailer Error: ' . $mail->ErrorInfo);
	    error_log($e);
	    return false;
	}
    } else {
	$mail->isQmail();
	$mail->preSend();
	//error_log( $mail->getSentMIMEMessage() );

	$client = SesClient::factory(array(
	    'region' => 'us-east-1',
	    'version' => '2010-12-01'
	));

	$origErrorLog = ini_get("error_log");

	try {
	    ini_set("display_errors", 1);
	    ini_set("error_log", "/tmp/ses-response.log");

	    $result = $client->sendRawEmail(
		    array(
			'Source' => WEBSITE_EMAIL_ADDY,
			'RawMessage' => array(
			    'Data' => $mail->getSentMIMEMessage()
			)
		    )
	    );

	    if (!$result) {
		error_log(" email fail ");
		return false;
	    }
	} catch (Exception $e) {
	    error_log(" email fail " . $e->getMessage());
	    return false;
	} finally {
	    ini_set("error_log", $origErrorLog); // temp
	}
    }

    return true;
}

function isEmailBanned($emailAddressToSendTo) {
    if (!is_null($emailAddressToSendTo)) {
	$sql = "SELECT * FROM bad_emails WHERE email_address=?";
	$args = array($emailAddressToSendTo);
	$bannedAddressResult = DbAuth::getObject($sql, $args);
	if ($bannedAddressResult) {
	    if ($bannedAddressResult['is_permanent']) {
		return true;
	    } else {
		// how long has this ban been in effect? can we clear it out ?
		$dateBanned = strtotime($bannedAddressResult['date_banned']);
		$banExpires = $dateBanned + (60 * 60); // if the ban is over an hour old delete it
		if ($banExpires < time()) {
		    DbAuth::query("DELETE FROM bad_emails WHERE id = {$bannedAddressResult['id']}");
		    return true;
		}
	    }
	}
    }
    return false;
}

function isDeviceBannedFromSendingEmail($platform, $banDeviceId, $deviceModel) {
    $sql = "SELECT * FROM banned_from_sending_email WHERE platform=? AND device_id=? AND device_model=? AND fail_count>=5";
    $args = array($platform, $banDeviceId, $deviceModel);
    $deviceBanExists = (DbAuth::objectExists($sql, $args));
    return $deviceBanExists;
}

function sendPasswordRecoveryEmail($loginId, $email, $hash, $language, $timestamp) {

    $preText = file_get_contents(TXT_DIR . "/{$language}/new_password.html");
    $link = "https://" . HOSTNAME . INSTALL_PATH . "/reset.php?l=$loginId&t=$timestamp&code=$hash&language=$language";
    $body = str_replace("{RESET_PASSWORD_URL}", $link, $preText);
    $subject = "Big Blue Bubble password recovery";

    return sendEmailMessage($email, $subject, $body);
}

function logBadEmailRequest($platform, $banDeviceId, $deviceModel) {
    if (is_null($platform) || is_null($banDeviceId) || is_null($deviceModel))
	return false;

    $sql = "INSERT INTO banned_from_sending_email SET platform=?, device_id=?, device_model=?, fail_count=1
				ON DUPLICATE KEY UPDATE fail_count=fail_count+1";
    $args = array($platform, $banDeviceId, $deviceModel);
    DbAuth::query($sql, $args);

    return true;
}

function getBounceCodes() {
    // get bannable codes from cache (if they don't exist load them from the DB and cache them)
    $bounceCodes = CacheWrapper::get('bounce_codes');
    if (is_null($bounceCodes) || !$bounceCodes) {
	//error_log("Loading bounce codes from DB");
	$result = DbAuth::getObjects('SELECT * FROM bounce_lookup');
	$bounceCodes = array();
	foreach ($result as $row) {
	    $bounceCodes[] = $row;
	}
	$jsonBounceMessages = json_encode($bounceCodes);
	CacheWrapper::set('bounce_codes', $jsonBounceMessages, CacheWrapper::TIMEOUT_SIXTY_MINUTES);
	$bounceCodes = $jsonBounceMessages;
    }
    return $bounceCodes;
}

function getDataFromUrl($url, $trustAll = true, $headers = null) {
    $ch = curl_init();
    $timeout = 5;
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $trustAll); //TODO: configure to trust specific sites
    if ($headers)
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $data = curl_exec($ch);

    if (curl_errno($ch)) {
	error_log('Curl error: ' . curl_error($ch));
    }
    curl_close($ch);
    return $data;
}

function postDataToUrl($url, $fields, $maxExecutionTime = null, $curlTimeout = 5) {

    if (!is_null($maxExecutionTime)) {
	ini_set('max_execution_time', $maxExecutionTime);
    }


    //url-ify the data for the POST
    $fields_string = "";
    foreach ($fields as $key => $value) {
	$fields_string .= $key . '=' . $value . '&';
    }

    //$header = getCurlAuthHeaders();

    $ch = curl_init();
    //curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $curlTimeout);
    curl_setopt($ch, CURLOPT_POST, count($fields));
    curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
	'Accept: application/json',
	'User-Agent: curl', # Apple requires a user agent header at the token endpoint
    ]);

    $data = curl_exec($ch);
    if (curl_errno($ch)) {
	echo 'Curl error: ' . curl_error($ch);
    }
    curl_close($ch);

    return $data;
}

function isSlimException($e) {
    $typeName = "Slim\Exception";
    $className = get_class($e);
    if (substr($className, 0, strlen($typeName)) === $typeName)
	return true;

    return false;
}

function validGUID($full_guid) {
    // strip out dashes if they exist
    $stripped_guid = str_replace("-", "", $full_guid);

    // check for known bad ones
    if ($stripped_guid === '00000000000000000000000000000000')
	return FALSE;

    // guids are 32 length strings of alpha numeric characters
    return (strlen($stripped_guid) == 32 && ctype_alnum($stripped_guid));
}
