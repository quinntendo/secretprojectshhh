<?php
class GlobalAchievementSettings {

	private static $settings = array();

	private static function load()
 	{
		$s = CacheWrapper::get("ga_settings");
		if(empty($settings)){
			$result = DbAuth::getObjects("SELECT * FROM ga_settings");
			foreach($result as $row){
				$s[trim($row['setting'])] = trim($row['value']);
			}
		}
		CacheWrapper::set('ga_settings', $s, 60);
		GlobalAchievementSettings::$settings = $s;
 	}

	public static function get($key){
		if(empty(GlobalAchievementSettings::$settings)){
			GlobalAchievementSettings::load();
		}
		return GlobalAchievementSettings::$settings[$key];
	}
}
