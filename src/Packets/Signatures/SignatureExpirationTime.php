<?php

namespace OpenPGP\Packets\Signatures;

class SignatureExpirationTime extends Sub
{
    function read()
    {
        $this->data = $this->read_timestamp();
    }

    function body()
    {
        return pack('N', $this->data);
    }
}
