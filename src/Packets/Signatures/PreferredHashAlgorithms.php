<?php

namespace OpenPGP\Packets\Signatures;

class PreferredHashAlgorithms extends Sub
{
    function read()
    {
        $this->data = [];
        while (strlen($this->input) > 0) {
            $this->data[] = ord($this->read_byte());
        }
    }

    function body()
    {
        $bytes = '';
        foreach ($this->data as $algo) {
            $bytes .= chr($algo);
        }

        return $bytes;
    }
}
