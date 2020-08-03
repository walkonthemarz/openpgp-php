<?php

namespace OpenPGP\Packets\Signatures;

class RegularExpression extends Sub
{
    function read()
    {
        $this->data = substr($this->input, 0, -1);
    }

    function body()
    {
        return $this->data . chr(0);
    }
}
