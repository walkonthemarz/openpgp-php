<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Crypt\Symmetric;
use OpenPGP\Crypt\RSA;
use OpenPGP\Message;

class Encryption extends TestCase {
    public function oneSymmetric($algorithm) {
        $data = new LiteralData('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
        $encrypted = Symmetric::encrypt('secret', new Message(array($data)), $algorithm);
        $encrypted = Message::parse($encrypted->to_bytes());
        $decrypted = Symmetric::decryptSymmetric('secret', $encrypted);
        $this->assertEquals($decrypted[0]->data, 'This is text.');
    }

    public function testEncryptSymmetric3DES() {
        $this->oneSymmetric(2);
    }

    public function testEncryptSymmetricCAST5() {
        $this->oneSymmetric(3);
    }

    public function testEncryptSymmetricBlowfish() {
        $this->oneSymmetric(4);
    }

    public function testEncryptSymmetricAES128() {
        $this->oneSymmetric(7);
    }

    public function testEncryptSymmetricAES192() {
        $this->oneSymmetric(8);
    }

    public function testEncryptSymmetricAES256() {
        $this->oneSymmetric(9);
    }

    public function testEncryptSymmetricTwofish() {
        if(Symmetric::getCipher(10)[0]) {
            $this->oneSymmetric(10);
        }
    }

    public function testEncryptAsymmetric() {
        $key = Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
        $data = new LiteralData('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
        $encrypted = Symmetric::encrypt($key, new Message(array($data)));
        $encrypted = Message::parse($encrypted->to_bytes());
        $decryptor = new RSA($key);
        $decrypted = $decryptor->decrypt($encrypted);
        $this->assertEquals($decrypted[0]->data, 'This is text.');
    }
}
