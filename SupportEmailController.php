<?php

require_once(COMMON_DIR . '/Zip.php');
$zip = new Zip();

class SupportEmailController extends ControllerBase {

    public function init() {
	$this->gameId = $this->reqParam(parent::GAME_ID);
    }

    // public function preflight()
    // {
    // header("Access-Control-Allow-Origin: *");
    // header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Accept, Origin, Host, content-length, Connection, User-Agent, Referer, Accept-Encoding, Accept-Language");
    // header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS");
    // }

    public function sendEmail() {
	$emailRequest = json_decode(file_get_contents('php://input'));

	// Make sure the e-mail isn't banned
	if (isEmailBanned($emailRequest->email)) {
	    //print( "BANNED" );
	    return;
	}

	$hashSignature = '';
	$capturedInfo = '';
	// Create the has to use - ignore 'files'
	foreach ($emailRequest as $key => $value) {
	    if ($key !== 'files')
		$hashSignature .= $value;

	    // Capture all the extra data provided
	    if ($key !== 'files' && $key !== 'subject' && $key !== 'message' && $key !== 'email')
		$capturedInfo .= "{$key}: {$value}<br/>";
	}

	$hash = md5($hashSignature);

	// Make sure this e-mail hasn't been send before
	$cacheValue = CacheWrapper::get("csr_email_{$hash}");
	if ($cacheValue != null) {
	    //print( "ALREADY SENT" );
	    return;
	}

	$message = isset($emailRequest->version) && $emailRequest->version > 1 ? base64_decode($emailRequest->message) : $emailRequest->message;

	$emailBody = file_get_contents(TXT_DIR . "/en/csr_email.html");
	$emailBody = str_replace("{name}", $emailRequest->name, $emailBody);
	$emailBody = str_replace("{email}", $emailRequest->email, $emailBody);
	$emailBody = str_replace("{message}", $message, $emailBody);
	$emailBody = str_replace("{info}", $capturedInfo, $emailBody);

	// Put the hash in cache for a bit so we don't try to resend
	CacheWrapper::set("csr_email_{$hash}", $hash, 5);

	$gameSettings = getGameSettings($this->gameId);
	$supportEmail = $gameSettings['support_email'];
	$split = explode('|', $supportEmail);
	$supportEmail = array(
	    'email' => sizeof($split) == 1 ? $split[0] : $split[1],
	    'name' => sizeof($split) == 1 ? '' : $split[0]
	);

	$supportBCC = array_key_exists('support_bcc', $gameSettings) ? $gameSettings['support_bcc'] : null;
	if ($supportBCC != null && strlen($supportBCC) > 0) {
	    $supportBCC = explode(',', $supportBCC);
	    foreach ($supportBCC as $key => $value) {
		$split = explode('|', $value);
		$supportBCC[$key] = array(
		    'email' => sizeof($split) == 1 ? $split[0] : $split[1],
		    'name' => sizeof($split) == 1 ? '' : $split[0]
		);
	    }
	} else {
	    $supportBCC = null;
	}


	// Get file data out
	$attachments = array();
	$files = array_key_exists('files', $emailRequest) ? $emailRequest->files : null;
	if ($files != null) {
	    $filesStr = base64_decode($files);
	    $filePairs = explode('|', $filesStr);
	    $files = array();

	    foreach ($filePairs as $filePairStr) {
		$filePair = explode('!', $filePairStr);
		$files[str_replace(':', '/', $filePair[0])] = $filePair[1];
	    }

	    $zip = new Zip();
	    foreach ($files as $key => $value) {
		if (strpos($value, '{') !== FALSE) // Dirty
		    $zip->addFile($value, $key);
		else
		    $zip->addFile(base64_decode($value), $key);
	    }

	    $attachments['contents.zip'] = $zip->getZipData();
	}

	// $this->preflight();

	$subject = isset($emailRequest->version) && $emailRequest->version > 1 ? base64_decode($emailRequest->subject) : $emailRequest->subject;

	//print( $emailBody );
	/*
	error_log("*****************************");
	error_log("'Contact Form'");
	error_log(print_r($supportEmail, true));
	error_log(print_r($supportBCC, true));
	error_log(print_r($emailRequest->email, true));
	error_log(print_r($emailRequest->name, true));
	error_log(print_r($subject, true));
	error_log(print_r($emailBody, true));
	error_log(print_r($attachments, true));
	error_log("******************************");
	*/
	sendEmailComplex(
		'Contact Form',
		array($supportEmail),
		$supportBCC,
		array(array('email' => $emailRequest->email, 'name' => $emailRequest->name)),
		$subject,
		$emailBody,
		null,
		$attachments
	);
	echo '{"result":true}';
    }

}
