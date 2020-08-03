<?php

require_once( dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Packets\PublicKey;
use OpenPGP\Packets\SecretKey;
use OpenPGP\Packets\UserID;

$rsa = new phpseclib\Crypt\RSA();
$k = $rsa->createKey(512);
$rsa->loadKey($k['privatekey']);

$nkey = new SecretKey(array(
   'n' => $rsa->modulus->toBytes(),
   'e' => $rsa->publicExponent->toBytes(),
   'd' => $rsa->exponent->toBytes(),
   'p' => $rsa->primes[2]->toBytes(),
   'q' => $rsa->primes[1]->toBytes(),
   'u' => $rsa->coefficients[2]->toBytes()
));

$uid = new UserID('Test <test@example.com>');

$wkey = new OpenPGP\Crypt\RSA($nkey);
$m = $wkey->sign_key_userid(array($nkey, $uid));

// Serialize private key
print OpenPGP\Pgp::enarmor($m->to_bytes(), \OpenPGP\Pgp::MARKER_PRIVATE_KEY);

// Serialize public key message
$pubm = clone($m);
$pubm[0] = new PublicKey($pubm[0]);

$public_bytes = $pubm->to_bytes();
