<?php

namespace OpenPGP\Packets\Signatures;

class SignersUserID extends Sub
{
    function read()
    {
        $this->data = $this->input;
    }

    function body()
    {
        return $this->data;
    }
}
