<?php

namespace OpenPGP\Packets\Signatures;

class PreferredKeyServer extends Sub
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
