<?php
require_once( dirname(__FILE__) . '/../vendor/autoload.php');

use OpenPGP\Message;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Crypt\Symmetric;
use OpenPGP\Crypt\RSA;

$key = Message::parse(file_get_contents(dirname(__FILE__) . '/../tests/data/helloKey.gpg'));
$data = new LiteralData('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
$encrypted = Symmetric::encrypt($key, new Message(array($data)));

// Now decrypt it with the same key
$decryptor = new RSA($key);
$decrypted = $decryptor->decrypt($encrypted);

var_dump($decrypted);
