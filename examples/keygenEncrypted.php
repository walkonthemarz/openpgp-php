<?php

require_once(dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Packets\SecretKey;
use OpenPGP\Packets\UserID;
use OpenPGP\Crypt\RSA;
use OpenPGP\Crypt\Symmetric;

$rsa = new \phpseclib\Crypt\RSA();
$k   = $rsa->createKey(512);
$rsa->loadKey($k['privatekey']);

$nkey = new SecretKey([
    'n' => $rsa->modulus->toBytes(),
    'e' => $rsa->publicExponent->toBytes(),
    'd' => $rsa->exponent->toBytes(),
    'p' => $rsa->primes[2]->toBytes(),
    'q' => $rsa->primes[1]->toBytes(),
    'u' => $rsa->coefficients[2]->toBytes(),
]);

$uid = new UserID('Test <test@example.com>');

$wkey = new RSA($nkey);
$m    = $wkey->sign_key_userid([$nkey, $uid]);
$m[0] = Symmetric::encryptSecretKey("password", $nkey);

// Serialize encrypted private key
print OpenPGP\Pgp::enarmor($m->to_bytes(), OpenPGP\Pgp::MARKER_PRIVATE_KEY);
