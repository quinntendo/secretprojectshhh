<?php

/*

  WHEN ADDING ITEMS, ADD THEM TO THE END OF THE LIST, NEVER EVER IN THE MIDDLE, KAT

 */

class ResponseCode {

    const AUTH_ERROR_USERNAME = 1;
    const AUTH_ERROR_PASSWORD = 2;
    const AUTH_ERROR_INVALID_TYPE = 3;
    const AUTH_ERROR_MISSING_DATA = 4;
    const AUTH_ERROR_LOGIN_FAILED = 5;
    const ERROR_BAD_USERNAME_MATCH = 6;
    const ERROR_BAD_PASSWORD_MATCH = 7;
    const ERROR_LOGIN_ALREADY_EXISTS = 8;
    const ERROR_BAD_EMAIL_ADDRESS = 9;
    const AUTH_ACCOUNT_UNVERIFIED = 10;
    const ERROR_GAME_SERVER_NOT_FOUND = 11;
    const EMAIL_ADDRESS_NOT_FOUND = 12;
    const CONNECTION_ERROR = 13;
    const SERVER_MESSAGE = 14;
    const BIND_ERROR_LOGIN_ALREADY_BOUND = 15;
    const BIND_ERROR_TYPE_ALREADY_BOUND = 16;
    const AUTH_ERROR_FACEBOOK_AUTH_FAILED = 17;
    const FRIEND_ALREADY_EXISTS = 18;
    const FRIEND_ACCOUNT_NOT_FOUND = 19;
    const GENERAL_ERROR = 20;
    const CLIENT_MIN_VERSION_ERROR = 21;
    const ERROR_EMAIL_BOUNCE = 22;
    const ERROR_EMAIL_MAX_FAILS = 23;
    const AUTH_ERROR_GAMECENTER_AUTH_FAILED = 24;
    const BIND_ERROR_GAME_CONFLICT = 25;
    const AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED = 26;
    const AUTH_ERROR_AMAZON_AUTH_FAILED = 27;
    const ERROR_NO_GAME_DATA_FOR_ACCOUNT = 28;
    const AUTH_TOKEN_MISSING = 29;
    const AUTH_TOKEN_PERMISSIONS = 30;
    const AUTH_INVALID_CLIENT_TOKEN = 31;
    const AUTH_INVALID_SERVER_TOKEN = 32;
    const GA_REWARD_NOT_FOUND = 33;
    const AUTH_TOO_MANY_ACCOUNTS = 34;
    const AUTH_GAME_CONFIG_NOT_FOUND = 35;
    const AUTH_GDPR_CONSENT_REQUIRED = 36;
    const AUTH_TOKEN_EXPIRED = 37;
    const AUTH_ERROR_APPLE_AUTH_FAILED = 38;
    const AUTH_ERROR_REFRESH_TOKEN_AUTH_FAILED = 39;
    const AUTH_ERROR_CREDENTIALS_EXPIRED = 40;
    const AUTH_ERROR_STEAM_AUTH_FAILED = 41;

    static function getMessage($messageType) {
	$messages = array(
	    self::AUTH_ERROR_USERNAME => 'Username does not exist',
	    self::AUTH_ERROR_PASSWORD => 'Invalid password',
	    self::AUTH_ERROR_INVALID_TYPE => 'Invalid account type',
	    self::AUTH_ERROR_MISSING_DATA => 'Required argument missing',
	    self::AUTH_ERROR_LOGIN_FAILED => 'Login failed',
	    self::ERROR_BAD_USERNAME_MATCH => 'Usernames do not match',
	    self::ERROR_BAD_PASSWORD_MATCH => 'Passwords do not match',
	    self::ERROR_LOGIN_ALREADY_EXISTS => 'The username is already in use',
	    self::ERROR_BAD_EMAIL_ADDRESS => 'The email address is invalid',
	    self::AUTH_ACCOUNT_UNVERIFIED => 'The email address has not been verified',
	    self::ERROR_GAME_SERVER_NOT_FOUND => 'Could not find the game server id based on the hostname provided',
	    self::EMAIL_ADDRESS_NOT_FOUND => 'Email address not found',
	    self::CONNECTION_ERROR => 'Connection error',
	    self::SERVER_MESSAGE => 'Server error',
	    self::BIND_ERROR_LOGIN_ALREADY_BOUND => 'Login info is already bound to another account',
	    self::BIND_ERROR_TYPE_ALREADY_BOUND => 'A login of this type is already bound to this account',
	    self::AUTH_ERROR_FACEBOOK_AUTH_FAILED => 'Facebook failed to validate user on the server',
	    self::FRIEND_ALREADY_EXISTS => 'These users are already friends.',
	    self::FRIEND_ACCOUNT_NOT_FOUND => 'No account found for that friend code.',
	    self::GENERAL_ERROR => "An error has occured",
	    self::CLIENT_MIN_VERSION_ERROR => "The min client version is too low to play this game.",
	    self::ERROR_EMAIL_BOUNCE => "The email address you provided probably has a typo and cannot receive mail. Please contact support to resolve this issue.",
	    self::ERROR_EMAIL_MAX_FAILS => "Your device has been banned from sending emails. Please contact support to resolve this issue.",
	    self::AUTH_TOO_MANY_ACCOUNTS => "Too many accounts have been created from your IP address.",
	    self::BIND_ERROR_GAME_CONFLICT => "Accounts contain same game id.",
	    self::AUTH_ERROR_GOOGLEPLAY_AUTH_FAILED => "Google Play authorization failed.",
	    self::AUTH_ERROR_AMAZON_AUTH_FAILED => "Amazon authorization failed.",
	    self::ERROR_NO_GAME_DATA_FOR_ACCOUNT => "Account has no data for this game.",
	    self::AUTH_TOKEN_MISSING => "No token was present when required",
	    self::AUTH_TOKEN_PERMISSIONS => "Invalid permissions",
	    self::AUTH_INVALID_CLIENT_TOKEN => "Expected client token, server token used",
	    self::AUTH_INVALID_SERVER_TOKEN => "Expected server token, client token used",
	    self::AUTH_ERROR_GAMECENTER_AUTH_FAILED => "Game center authorization failed.",
	    self::GA_REWARD_NOT_FOUND => "Global Achievement reward not found.",
	    self::AUTH_GAME_CONFIG_NOT_FOUND => "Game config not found for: ",
	    self::AUTH_GDPR_CONSENT_REQUIRED => "GDPR consent required",
	    self::AUTH_TOKEN_EXPIRED => "Token Expired",
	    self::AUTH_ERROR_APPLE_AUTH_FAILED => "Apple authorization failed.",
	    self::AUTH_ERROR_REFRESH_TOKEN_AUTH_FAILED => "Refresh Token authorization failed.",
	    self::AUTH_ERROR_CREDENTIALS_EXPIRED => "Credentials are expired.",
	    self::AUTH_ERROR_STEAM_AUTH_FAILED => "Steam authorization failed."
	);
	return $messages[$messageType];
    }

}

?>
