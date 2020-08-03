<?php
require_once( dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Message;
use OpenPGP\Packets\SecretKey;
use OpenPGP\Crypt\Symmetric;
use OpenPGP\Crypt\RSA;
use OpenPGP\Pgp;

// USAGE: php examples/deASCIIdeCrypt.php secretkey.asc password message.asc
// This will fail if the algo on key or message is not 3DES or AES
$keyASCII = file_get_contents($argv[1]);
$msgASCII = file_get_contents($argv[3]);

$keyEncrypted = Message::parse(Pgp::unarmor($keyASCII, 'PGP PRIVATE KEY BLOCK'));

// Try each secret key packet
foreach($keyEncrypted as $p) {
	if(!($p instanceof SecretKey)) continue;

	$key = Symmetric::decryptSecretKey($argv[2], $p);

	$msg = Message::parse(Pgp::unarmor($msgASCII, 'PGP MESSAGE'));

	$decryptor = new RSA($key);
	$decrypted = $decryptor->decrypt($msg);

	var_dump($decrypted);
}
