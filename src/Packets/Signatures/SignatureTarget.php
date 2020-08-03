<?php

namespace OpenPGP\Packets\Signatures;

class SignatureTarget extends Sub
{
    public $key_algorithm;
    public $hash_algorithm;

    function read()
    {
        $this->key_algorithm  = ord($this->read_byte());
        $this->hash_algorithm = ord($this->read_byte());
        $this->data           = $this->input;
    }

    function body()
    {
        return chr($this->key_algorithm) . chr($this->hash_algorithm) . $this->data;
    }

}
