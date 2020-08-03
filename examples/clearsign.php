<?php

require_once(dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Message;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Crypt\RSA;
use OpenPGP\Pgp;

/* Parse secret key from STDIN, the key must not be password protected */
$wkey = Message::parse(file_get_contents('php://stdin'));
$wkey = $wkey[0];

$string = "This\nis\na\ntest.";

/* Create a new literal data packet */
$data = new LiteralData($string, ['format' => 'u', 'filename' => 'stuff.txt']);
$data->normalize(true); // Clearsign-style normalization of the LiteralDataPacket

/* Create a signer from the key */
$sign = new RSA($wkey);

/* The message is the signed data packet */
$m = $sign->sign($data);

/* Generate clearsigned data */
$packets = $m->signatures()[0];
echo "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n";
// Output normalised data.  You could convert line endings here
// without breaking the signature, but do not add any
// trailing whitespace to lines.
echo preg_replace("/^-/", "- -", $packets[0]->data) . "\n";
echo Pgp::enarmor($packets[1][0]->to_bytes(), "PGP SIGNATURE");
