<?php

use Aws\ElastiCache\ElastiCacheClient;

class CacheWrapper {

	const TIMEOUT_THIRTY_SECONDS = 30;
	const TIMEOUT_SIXTY_SECONDS = 60;
	const TIMEOUT_FIVE_MINUTES = 300;
	const TIMEOUT_TEN_MINUTES = 600;
	const TIMEOUT_FIFTEEN_MINUTES = 900;
	const TIMEOUT_TWENTY_MINUTES = 1200;
	const TIMEOUT_THIRTY_MINUTES = 1800;
	const TIMEOUT_SIXTY_MINUTES = 3600;
	const TIMEOUT_TWO_HOURS = 7200;
	const TIMEOUT_FOUR_HOURS = 14400;
	const TIMEOUT_ONE_DAY = 86400;

	private static $client = null;

	//connect to the elasticache
	public static function connect($endpoint = null, $port = 11211) {
		if (class_exists("Memcached")) {
			self::$client = new Memcached();
			self::$client->addServer($endpoint, $port);
		} else if (class_exists("Memcache")) {
			self::$client = new Memcache();
			self::$client->connect($endpoint, $port);
		} else {
			error_log("No Memcache or Memcached classes available.");
			return false;
		}
	}

	public static function get($key) {
		return self::$client->get(CACHE_PREFIX . $key);
	}

	public static function set($key, $value, $expires) {
		try{
			if (class_exists("Memcached")) {
				if (!self::$client->set(CACHE_PREFIX . $key, $value, $expires)) {
					error_log("Memcached CACHE WRITE FAILED");
					throw new Exception();
					//die();
				}
			} else {
				if (!self::$client->set(CACHE_PREFIX . $key, $value, 0, $expires)) {
					error_log("Memcache CACHE WRITE FAILED");
					throw new Exception();
					//die();
				}
			}
		}catch(Exception $e){
			error_log($e->getTraceAsString());
		}
	}

	public static function delete($key) {
		self::$client->delete(CACHE_PREFIX . $key);
	}

}

?>
