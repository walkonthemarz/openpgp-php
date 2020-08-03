<?php

namespace OpenPGP\Packets\Signatures;

class ReasonforRevocation extends Sub
{
    public $code;

    function read()
    {
        $this->code = ord($this->read_byte());
        $this->data = $this->input;
    }

    function body()
    {
        return chr($this->code) . $this->data;
    }
}
