<?php

$language = isset($_REQUEST['lang']) ? $_REQUEST['lang'] : 'en';
define('DOWN_FOR_MAINTENANCE', false);

define('QUERY_DEBUG', false);
define('QUERY_DEBUG_STACKTRACE', false);

define("HOSTNAME", isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'auth.bbbgame.net'); //used in cron jobs
// THIS FILE NEEDS TO CONTAIN THE EMAIL and DB DEFINES FOR THE PROPER AUTH SERVER ONLY
require_once(dirname(__FILE__) . '/server_constants.php');

/* ACCOUNT TYPE CONSTANTS */
define('LOGIN_TYPE_FACEBOOK', 'fb');
define('LOGIN_TYPE_EMAIL', 'email');
define('LOGIN_TYPE_GAME_CENTER', 'gc');
define('LOGIN_TYPE_ANONYMOUS', 'anon');
define('LOGIN_TYPE_GOOGLE_PLAY', 'gp');
define('LOGIN_TYPE_AMAZON', 'amazon');
define('LOGIN_TYPE_MSM_ANONYMOUS', 'msm_anon');
define('LOGIN_TYPE_APPLE', 'apple');
define('LOGIN_TYPE_STEAM', 'steam');

$validAcctTypes = array(
    LOGIN_TYPE_FACEBOOK,
    LOGIN_TYPE_EMAIL,
    LOGIN_TYPE_GAME_CENTER,
    LOGIN_TYPE_ANONYMOUS,
    LOGIN_TYPE_GOOGLE_PLAY,
    LOGIN_TYPE_AMAZON,
    LOGIN_TYPE_MSM_ANONYMOUS,
    LOGIN_TYPE_APPLE,
    LOGIN_TYPE_STEAM
);


mb_internal_encoding("UTF-8");

require_once(COMMON_DIR . '/functions.php');
require_once(COMMON_DIR . '/ResponseCode.php');
require_once(COMMON_DIR . '/Authentication.trait.php');
require_once(COMMON_DIR . '/DbBase.php'); // contains the important code
require_once(COMMON_DIR . '/DbAuth.php'); // extends DbBase
require_once(COMMON_DIR . '/BBBSqsClient.php');
require_once(COMMON_DIR . '/BBBSnsClient.php');
require_once(COMMON_DIR . '/CacheWrapper.php');
require_once(COMMON_DIR . '/Encryption.php');
require_once(COMMON_DIR . '/BBBToken.php');
require_once(COMMON_DIR . '/UserGameConsent.php');
require_once(COMMON_DIR . '/SignInWithApple.php');

require_once(COMMON_DIR . '/GoogleAuthenticator/FixedBitNotation.php');
require_once(COMMON_DIR . '/GoogleAuthenticator/GoogleAuthenticatorInterface.php');
require_once(COMMON_DIR . '/GoogleAuthenticator/GoogleAuthenticator.php');
require_once(COMMON_DIR . '/GoogleAuthenticator/GoogleQrUrl.php');
require_once(COMMON_DIR . '/GoogleAuthenticator/RuntimeException.php');

require_once(INSTALL_DIR .'/aws-autoloader.php');

header('Cache-Control: no-cache');
header('Pragma: no-cache');
header("Content-Type: application/json; charset=utf-8");
header('P3P: CP="CAO PSA OUR"');

if (DOWN_FOR_MAINTENANCE) {
    $downMessages = array(
	'de' => 'An den Servern werden gerade Wartungsarbeiten ausgeführt. Bitte überprüfe später nochmals.',
	'en' => 'The servers are currently undergoing maintenance. Please check back soon.',
	'es' => 'Los servidores están actualmente en fase de mantenimiento. Por favor, vuelve a intentarlo más tarde.',
	'fr' => 'Les serveurs sont actuellement en cours de maintenance. Merci de patienter et de revenir plus tard.',
	'it' => 'I server sono attualmente in fase di manutenzione. Riprova più tardi.',
	'ja' => 'The servers are currently undergoing maintenance. Please check back soon',
	'pt' => 'Nesse momento os servidores estão em manutenção. Por favor, verifique novamente mais tarde.',
	'ru' => 'В данный момент серверы совершают обслуживание. Пожалуйста, попробуйте еще раз позже.'
    );
    $downMessage = (array_key_exists($lang, $downMessages)) ? $downMessages[$lang] : $downMessages['en'];
    sendErrorMessage(ResponseCode::SERVER_MESSAGE, $downMessage);
    die();
}

DbAuth::connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
CacheWrapper::connect(CACHE_HOST, CACHE_PORT);

$fbAppId = null;
if (isset($_REQUEST['g']) && !empty($_REQUEST['g'])) {
    $gameSettings = getGameSettings($_REQUEST['g']);
    $fbAppId = isset($gameSettings['fb_app_id']) ? $gameSettings['fb_app_id'] : null;
}

$requestedScript = $_SERVER['SCRIPT_NAME'];

/*
$apiFunctionCalled = '';
function shutdown()
{
    Global $apiFunctionCalled;
    error_log("Function $apiFunctionCalled");
    error_log("System Memory ".number_format(memory_get_peak_usage(true), 0, null, ','));
    error_log("Malloc Memory ".number_format(memory_get_peak_usage(false), 0, null, ','));
}
register_shutdown_function('shutdown');
*/
