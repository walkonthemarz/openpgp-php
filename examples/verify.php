<?php

require_once(dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Message;
use OpenPGP\Crypt\RSA;

/* Parse public key from STDIN */
$wkey = Message::parse(file_get_contents('php://stdin'));

/* Parse signed message from file named "t" */
$m = Message::parse(file_get_contents('t'));

/* Create a verifier for the key */
$verify = new RSA($wkey);

/* Dump verification information to STDOUT */
var_dump($verify->verify($m));
