<?php
namespace Tests;

use PHPUnit\Framework\TestCase;
use OpenPGP\Message;
use OpenPGP\Crypt\Symmetric;
use OpenPGP\Crypt\RSA;
use OpenPGP\Packets\CompressedData;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Packets\SecretKey;
use Exception;

class Decryption extends TestCase {
    public function oneSymmetric($pass, $cnt, $path) {
        $m = Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
        $m2 = Symmetric::decryptSymmetric($pass, $m);
        while($m2[0] instanceof CompressedData) $m2 = $m2[0]->data;
        foreach($m2 as $p) {
            if($p instanceof LiteralData) {
                $this->assertEquals($p->data, $cnt);
            }
        }
    }

    public function testDecrypt3DES() {
        $this->oneSymmetric("hello", "PGP\n", "symmetric-3des.gpg");
    }

    public function testDecryptCAST5() { // Requires mcrypt or openssl
        $this->oneSymmetric("hello", "PGP\n", "symmetric-cast5.gpg");
    }

    public function testDecryptBlowfish() {
        $this->oneSymmetric("hello", "PGP\n", "symmetric-blowfish.gpg");
    }

    public function testDecryptAES() {
        $this->oneSymmetric("hello", "PGP\n", "symmetric-aes.gpg");
    }

    public function testDecryptTwofish() {
        if(Symmetric::getCipher(10)[0]) {
            $this->oneSymmetric("hello", "PGP\n", "symmetric-twofish.gpg");
        }
    }

    public function testDecryptSessionKey() {
        $this->oneSymmetric("hello", "PGP\n", "symmetric-with-session-key.gpg");
    }

    public function testDecryptNoMDC() {
        $this->oneSymmetric("hello", "PGP\n", "symmetric-no-mdc.gpg");
    }

    public function testDecryptAsymmetric() {
        $m = Message::parse(file_get_contents(dirname(__FILE__) . '/data/hello.gpg'));
        $key = Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
        $decryptor = new RSA($key);
        $m2 = $decryptor->decrypt($m);
        while($m2[0] instanceof CompressedData) $m2 = $m2[0]->data;
        foreach($m2 as $p) {
            if($p instanceof LiteralData) {
                $this->assertEquals($p->data, "hello\n");
            }
        }
    }

    public function testDecryptRoundtrip() {
        $m = new Message(array(new LiteralData("hello\n")));
        $key = Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
        $em = Symmetric::encrypt($key, $m);

        foreach($key as $packet) {
            if(!($packet instanceof SecretKey)) continue;
            $decryptor = new RSA($packet);
            $m2 = $decryptor->decrypt($em);

            foreach($m2 as $p) {
                if($p instanceof LiteralData) {
                    $this->assertEquals($p->data, "hello\n");
                }
            }
        }
    }

    public function testDecryptSecretKey() {
        $key = Message::parse(file_get_contents(dirname(__FILE__) . '/data/encryptedSecretKey.gpg'));
        $skey = Symmetric::decryptSecretKey("hello", $key[0]);
        $this->assertSame(!!$skey, true);
    }

    public function testEncryptSecretKeyRoundtrip() {
        $key = Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
        $enkey = Symmetric::encryptSecretKey("password", $key[0]);
        $skey = Symmetric::decryptSecretKey("password", $enkey);
        $this->assertEquals($key[0], $skey);
    }

    public function testAlreadyDecryptedSecretKey() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Data is already unencrypted");
        $key = Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
        Symmetric::decryptSecretKey("hello", $key[0]);
    }
}
