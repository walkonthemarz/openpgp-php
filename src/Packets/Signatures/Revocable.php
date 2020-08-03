<?php

namespace OpenPGP\Packets\Signatures;

class Revocable extends Sub
{
    function read()
    {
        $this->data = (ord($this->input) != 0);
    }

    function body()
    {
        return chr($this->data ? 1 : 0);
    }
}
