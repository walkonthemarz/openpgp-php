<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use OpenPGP\Message;
use OpenPGP\Crypt\RSA;

class KeyVerification extends TestCase {
    public function oneKeyRSA($path) {
        $m = Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
        $verify = new RSA($m);
        $this->assertSame($verify->verify($m), $m->signatures());
    }

    public function testHelloKey() {
        $this->oneKeyRSA("helloKey.gpg");
    }
}
