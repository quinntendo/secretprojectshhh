<?php

use Aws\Sns\SnsClient;


class BBBSnsClient {

	private static $sqs = null;
	private static $connected = false;
	
	public static function connect($awsRegion, $awsKey=null, $awsSecret=null) {
		
		$configArray = array('region' => $awsRegion);
		if(!is_null($awsKey) && !is_null($awsSecret)){
			$configArray['key'] = $awsKey;
			$configArray['secret'] = $awsSecret;
		}
		self::$connected = true;
		self::$sqs = SnsClient::factory($configArray);
	}

	public static function publish($topicArn, $messageString, $region=null) {
		if(!self::$connected){
			self:connect($region);
		}
		self::$sqs->publish(array(
			'TopicArn' => $topicArn,
			'Message' => $messageString
		));
	}

}
