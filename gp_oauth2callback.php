<?php

error_log("********************* START ************************");
error_log(print_r($REQUEST, true));
error_log(file_get_contents('php://input'));
error_log("********************** END **************************");
