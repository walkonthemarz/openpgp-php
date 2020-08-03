<?php

namespace OpenPGP\Packets\Signatures;

class KeyFlags extends Sub
{
    function __construct($flags = [])
    {
        parent::__construct();
        $this->flags = $flags;
    }

    function read()
    {
        $this->flags = [];
        while ($this->input) {
            $this->flags[] = ord($this->read_byte());
        }
    }

    function body()
    {
        $bytes = '';
        foreach ($this->flags as $f) {
            $bytes .= chr($f);
        }

        return $bytes;
    }
}
