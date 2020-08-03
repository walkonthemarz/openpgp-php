<?php

namespace OpenPGP\Packets\Signatures;

class KeyExpirationTime extends Sub
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

