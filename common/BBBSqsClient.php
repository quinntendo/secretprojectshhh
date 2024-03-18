<?php

use Aws\Sqs\SqsClient;

class BBBSqsClient {

	private static $sqs = null;
	private static $connected = false;
	
	public static function connect($awsRegion, $awsKey=null, $awsSecret=null) {
		
		$configArray = array('region' => $awsRegion);
		if(!is_null($awsKey) && !is_null($awsSecret)){
			$configArray['key'] = $awsKey;
			$configArray['secret'] = $awsSecret;
		}
		self::$connected = true;
		self::$sqs = SqsClient::factory($configArray);
	}

	public static function sendMessage($queueURL, $messageString, $region=null) {
		if(!self::$connected){
			self:connect($region);
		}
		self::$sqs->sendMessage(array(
			'QueueUrl' => $queueURL,
			'MessageBody' => $messageString
		));
	}

}
