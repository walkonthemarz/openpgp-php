<?php

require_once(dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Message;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Crypt\RSA;

/* Parse secret key from STDIN, the key must not be password protected */
$wkey = Message::parse(file_get_contents('php://stdin'));
$wkey = $wkey[0];

/* Create a new literal data packet */
$data = new LiteralData('This is text.', ['format' => 'u', 'filename' => 'stuff.txt']);

/* Create a signer from the key */
$sign = new RSA($wkey);

/* The message is the signed data packet */
$m = $sign->sign($data);

/* Output the raw message bytes to STDOUT */
echo $m->to_bytes();
