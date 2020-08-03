<?php

namespace OpenPGP\Packets\Signatures;

use OpenPGP\Packets\Signature;

class EmbeddedSignature extends Signature
{
    // TODO: This is duplicated from subpacket... improve?
    function __construct($data = null)
    {
        parent::__construct($data);
        $this->tag = array_search(substr(substr(get_class($this), 8 + 16), 0, -6), Signature::$subpacket_types);
    }

    function header_and_body()
    {
        $body = $this->body(); // Get body first, we will need it's length
        $size = chr(255) . pack('N', strlen($body) + 1); // Use 5-octet lengths + 1 for tag as first packet body octet
        $tag  = chr($this->tag);

        return ['header' => $size . $tag, 'body' => $body];
    }
}
