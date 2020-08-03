<?php

namespace OpenPGP\Packets\Signatures;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.4
 */
class SignatureCreationTime extends Sub
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
