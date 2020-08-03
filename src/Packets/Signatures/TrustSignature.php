<?php

namespace OpenPGP\Packets\Signatures;

class TrustSignature extends Sub
{
    function read()
    {
        $this->depth = ord($this->input[0]);
        $this->trust = ord($this->input[1]);
    }

    function body()
    {
        return chr($this->depth) . chr($this->trust);
    }
}
