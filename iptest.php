<?php
//require('./config.php');
/*
$message = '{"account_id":"qkbpy9c2dt","user_game_ids":["6bcww7pbnb"],"game":"1","token_version":1,"generated_on":1620849845,"expires_at":1620851045,"username":"mymbdb22fr4q","login_type":"anon"}';
$vector = 'zq3zn4dx2h3k4im6';
$secret = 'y26ju5h9r28eh3h2';
$enc = Encryption::encrypt($message, $vector, $secret);
$dec = Encryption::decrypt($enc, $vector, $secret);

echo $message.'\n'.$enc.'\n'.$dec;
*/
print("System Memory ".number_format(memory_get_peak_usage(true), 0, null, ','))."\r\n";
print("Malloc Memory ".number_format(memory_get_peak_usage(false), 0, null, ','));

?>


