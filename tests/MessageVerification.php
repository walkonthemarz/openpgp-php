<?php
namespace Tests;

use PHPUnit\Framework\TestCase;
use OpenPGP\Message;
use OpenPGP\Crypt\RSA;
use OpenPGP\Packets\LiteralData;

class MessageVerification extends TestCase {
    public function oneMessageRSA($pkey, $path) {
        $pkeyM = Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $pkey));
        $m = Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
        $verify = new RSA($pkeyM);
        $this->assertSame($verify->verify($m), $m->signatures());
    }

    public function testUncompressedOpsRSA() {
        $this->oneMessageRSA('pubring.gpg', 'uncompressed-ops-rsa.gpg');
    }

    public function testCompressedSig() {
        $this->oneMessageRSA('pubring.gpg', 'compressedsig.gpg');
    }

    public function testCompressedSigZLIB() {
        $this->oneMessageRSA('pubring.gpg', 'compressedsig-zlib.gpg');
    }

    public function testCompressedSigBzip2() {
        $this->oneMessageRSA('pubring.gpg', 'compressedsig-bzip2.gpg');
    }

    public function testSigningMessages() {
        $wkey = Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
        $data = new LiteralData('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
        $sign = new RSA($wkey);
        $m = $sign->sign($data)->to_bytes();
        $reparsedM = Message::parse($m);
        $this->assertSame($sign->verify($reparsedM), $reparsedM->signatures());
    }

    /*
      public function testUncompressedOpsDSA() {
        $this->oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa.gpg');
      }

      public function testUncompressedOpsDSAsha384() {
        $this->oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa-sha384.gpg');
      }
    */
}
