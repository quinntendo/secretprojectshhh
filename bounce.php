<?php

require('./config.php');
error_reporting(E_ALL);
$origErrorLog = ini_get("error_log");

ini_set("display_errors", 1);
//ini_set("error_log", "/tmp/ses-response.log");

if(isset($_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE']) && $_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE'] == 'SubscriptionConfirmation'){
    $inputData = json_decode(file_get_contents('php://input'));
    $message = $inputData->Message;
    $subscribeURL = $inputData->SubscribeURL;
    
    $body = "$message\r\n\r\n\r\n$subscribeURL";

    sendEmailMessage("timsa@bigbluebubble.com", "SNS Subscription Confirmation Message", $body);
}

$bannableStatusCodes = CacheWrapper::get('hard_bounce_codes');
$transientStatusCodes = CacheWrapper::get('soft_bounce_codes');
if (is_null($bannableStatusCodes) || !$bannableStatusCodes || is_null($transientStatusCodes) || !$transientStatusCodes) {
    $bounceCodes = json_decode(getBounceCodes());
    if (!is_array($bounceCodes)) {
	error_log("Can't load the bounce codes, ABORT");
	die();
    }
    $bannableStatusCodes = array();
    $transientStatusCodes = array();
    foreach ($bounceCodes as $bounceCode) {
	if ($bounceCode->bounce_type == 'Hard') {
	    $bannableStatusCodes[] = $bounceCode->bounce_code;
	}
	if ($bounceCode->bounce_type == 'Soft') {
	    $transientStatusCodes[] = $bounceCode->bounce_code;
	}
    }
    CacheWrapper::set('hard_bounce_codes', $bannableStatusCodes, CacheWrapper::TIMEOUT_SIXTY_MINUTES);
    CacheWrapper::set('soft_bounce_codes', $transientStatusCodes, CacheWrapper::TIMEOUT_SIXTY_MINUTES);
}

$jsonInputString = file_get_contents('php://input');
$inputData = json_decode($jsonInputString);
$message = json_decode($inputData->Message);

function doBan($emailAddress, $statusCode, $isPermanent, $message) {
    $sql = "INSERT INTO bad_emails SET email_address=?, status_code=?, date_banned=NOW(), is_permanent=?, bounce_code=? ON DUPLICATE KEY UPDATE status_code=?, date_banned=NOW(), is_permanent=?, bounce_code=?";
    $args = array($emailAddress, $statusCode, $isPermanent, json_encode($message), $statusCode, $isPermanent, json_encode($message));
    DbAuth::query($sql, $args);
}

if ($message->notificationType == "Bounce") {
    $bounce = $message->bounce;
    if ($bounce->bounceType == "Permanent" || $bounce->bounceType == "Transient") {

	$isPermanent = ($bounce->bounceType == "Transient") ? 0 : 1;

	$recipients = $bounce->bouncedRecipients;

	foreach ($recipients as $recipient) {
	    if (property_exists($recipient, 'status') && (in_array($recipient->status, $bannableStatusCodes) || in_array($recipient->status, $transientStatusCodes))) {
		$emailAddress = $recipient->emailAddress;

		// this message is matches the message id returned by SES when we sent the email. It's here in case we ever need it.
		//if(isset($recipient->mail))
		//	$messageId = $recipient->mail->messageId;

		doBan($emailAddress, $recipient->status, $isPermanent, $bounce);
	    } else {
		if(property_exists($recipient, 'status')){
		    error_log("Found a new status code $recipient->status for email $recipient->emailAddress");
		}else{
		    error_log("Found an empty status code for email $recipient->emailAddress");
		    error_log(print_r($recipient, true));
		}
	    }
	}
    }
} elseif ($message->notificationType == "Complaint") {
    $complaint = $message->complaint;
    $complainedRecipients = $complaint->complainedRecipients;

    $firstElement = $complainedRecipients[0];
    $emailAddress = $firstElement->emailAddress;
    doBan($emailAddress, "complaint", 1, $complaint);
}

ini_set("error_log", $origErrorLog);
