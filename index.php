<?php
require_once('./config.php');

$rawLang = (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
$lang = substr($rawLang, 0, 2);
switch ($lang) {
    case "de":
    case "en":
    case "es":
    case "fr":
    case "it":
    case "pt":
    case "ru":
	$language = $lang;
	break;
    default:
	$language = 'en'; //use EN for all other languages.
	break;
}

if(isset($_REQUEST['language']) && !empty($_REQUEST['language'])){
	$language = $_REQUEST['language'];
}
$messages = array(
    'de' => array(
	'EMAIL_NOT_VERIFIED' => 'E-Mail-Adresse wurde nicht bestätigt',
	'EMAIL_NOT_FOUND' => 'E-Mail-Adresse wurde nicht gefunden',
	'GENERAL_ERROR' => 'Es gab einen Fehler mit der Verarbeitung deiner Anfrage',
	'EMAIL_SENT' => 'Eine E-Mail wurde an die von dir angegebene Adresse versandt',
	'EMAIL_BLOCKED' => 'Die angegebene E-Mail-Adresse enthält möglicherweise einen Tippfehler und kann keine E-Mails empfangen. Bitte kontaktiere Support, um dieses Problem zu beheben'
    ),
    'en' => array(
	'EMAIL_NOT_VERIFIED' => 'Email address was not verified',
	'EMAIL_NOT_FOUND' => 'Email address was not found',
	'GENERAL_ERROR' => 'There was an error processing your request',
	'EMAIL_SENT' => 'An email has been sent to the email address you provided',
	'EMAIL_BLOCKED' => 'The email address you provided probably has a typo and cannot receive mail. Please contact support to resolve this issue.'
    ),
    'es' => array(
	'EMAIL_NOT_VERIFIED' => 'La dirección de correo electrónico no ha sido verificada',
	'EMAIL_NOT_FOUND' => 'La dirección de correo electrónico no se ha encontrado',
	'GENERAL_ERROR' => 'Error al procesar tu solicitud',
	'EMAIL_SENT' => 'Un correo electrónico ha sido enviado a la dirreción especificada',
	'EMAIL_BLOCKED' => 'La dirección de correo electrónico proporcionada puede tener un error tipográfico y no puede recibir correo. Ponte en contacto con el soporte para resolver este problema'
    ),
    'fr' => array(
	'EMAIL_NOT_VERIFIED' => 'L\'adresse email n\'a pas été vérifiée',
	'EMAIL_NOT_FOUND' => 'L\'adresse email n\'a pas été trouvée',
	'GENERAL_ERROR' => 'Il y a eu une erreur de traitement de votre demande',
	'EMAIL_SENT' => 'Un nouveau mot de passe a été envoyé à l\'adresse email indiquée',
	'EMAIL_BLOCKED' => 'L\'adresse e-mail fournie contient peut-être une faute de frappe et ne peut pas recevoir de courrier. S\'il te plaît, contacte l\'assistance pour résoudre ce problème'
    ),
    'it' => array(
	'EMAIL_NOT_VERIFIED' => 'L\'indirizzo di posta elettronica non è stato verificato',
	'EMAIL_NOT_FOUND' => 'L\'indirizzo di posta elettronica non è stato trovato',
	'GENERAL_ERROR' => 'Errore di elaborazione della tua richiesta',
	'EMAIL_SENT' => 'Una e-mail è stata inviata all\'indirizzo email che hai fornito.',
	'EMAIL_BLOCKED' => 'L\'indirizzo e-mail fornito potrebbe contenere un errore di battitura e non può ricevere la posta. Si prega di contattare il supporto per risolvere questo problema'
    ),
    'pt' => array(
	'EMAIL_NOT_VERIFIED' => 'O endereço de email não foi confirmado.',
	'EMAIL_NOT_FOUND' => 'O endereço de email não foi encontrado.',
	'GENERAL_ERROR' => 'Ocorreu um erro ao processar sua solicitação.',
	'EMAIL_SENT' => 'Um email foi enviado para o endereço de email fornecido por você.',
	'EMAIL_BLOCKED' => 'O endereço de e-mail fornecido pode ter um erro de digitação e não pode receber e-mails. Entre em contato com o suporte para resolver esse problema'
    ),
    'ru' => array(
	'EMAIL_NOT_VERIFIED' => 'Адрес электронной почты не верифицирован.',
	'EMAIL_NOT_FOUND' => 'Адрес электронной почты не найден.',
	'GENERAL_ERROR' => 'При обработке вашего запроса произошла ошибка.',
	'EMAIL_SENT' => 'Электронное письмо отправлено на адрес электронной почты, который вы указали.',
	'EMAIL_BLOCKED' => 'В указанном адресе электронной почты может быть опечатка, и вы не можете получать почту. Обратись в службу поддержки для решения этой проблемы'
    )
);
$message_type = null;
if (!empty($_POST)) {
    if (isset($_POST['email']) && isset($_POST['hash']) && isset($_POST['time'])) {
	$cEmail = $_POST['email'];
	$cTime = $_POST['time'];
	$cHash = $_POST['hash'];

	$realHash = md5(HASH_SEED . "_$cTime");
	if ($cHash == $realHash) {
	    $sendmail = true;
	    $sql = "SELECT id, account_id, username, verified FROM logins WHERE username=? AND login_type=?";
	    $sqlArgs = array($cEmail, LOGIN_TYPE_EMAIL);
	    $result = DbAuth::getObject($sql, $sqlArgs);
	    if ($result) {

		if ($result['verified'] == 0) {
		    if (isEmailBanned($cEmail)) {
			$message_type = 'EMAIL_BLOCKED';
		    } else {
			$message_type = 'EMAIL_NOT_VERIFIED';
		    }
		    $sendmail = false;
		}
		$email = $result['username'];

		$loginId = $result['id'];
		$accountId = $result['account_id'];
                $timestamp = time();
                
		// generate a new hash that wil be checked on reset.php
                $resetPasswordHash = md5(HASH_SEED . "{$accountId}_{$email}_{$timestamp}" . HASH_SEED);
		if ($sendmail) {

		    if (!isEmailBanned($cEmail)) {
			sendPasswordRecoveryEmail($loginId, $cEmail, $resetPasswordHash, $language, $timestamp);
			$message_type = 'EMAIL_SENT';
		    } else {
			$message_type = 'EMAIL_BLOCKED';
		    }
		}
	    } else {
		$message_type = 'EMAIL_NOT_FOUND';
	    }
	} else {
	    $message_type = 'GENERAL_ERROR';
	}
    } else {
	$message_type = 'GENERAL_ERROR';
    }
}

$time = time();
$hash = md5(HASH_SEED . "_$time");



$message = "";
if (!is_null($message_type)) {
    $message = "<h1>{$messages[$language][$message_type]}</h1>";
}

header("Content-Type: text/html; charset=utf-8");
include_once(TXT_DIR . "/" . $language . "/recover.php");
?>