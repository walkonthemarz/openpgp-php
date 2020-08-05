<?php

namespace OpenPGP\Packets;

use OpenPGP\S2k;

use OpenPGP\Pgp;
/**
 * OpenPGP Secret-Key packet (tag 5).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.3
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.3
 * @see http://tools.ietf.org/html/rfc4880#section-11.2
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class SecretKey extends PublicKey
{
    public $s2k_useage;
    public $s2k;
    public $symmetric_algorithm;
    public $private_hash;
    public $encrypted_data;

    function read()
    {
        parent::read(); // All the fields from PublicKey
        $this->s2k_useage = ord($this->read_byte());
        if ($this->s2k_useage == 255 || $this->s2k_useage == 254) {
            $this->symmetric_algorithm = ord($this->read_byte());
            $this->s2k                 = S2k::parse($this->input);
        } elseif ($this->s2k_useage > 0) {
            $this->symmetric_algorithm = $this->s2k_useage;
        }
        if ($this->s2k_useage > 0) {
            $this->encrypted_data = $this->input; // Rest of input is MPIs and checksum (encrypted)
        } else {
            $this->key_from_input();
            $this->private_hash = $this->read_bytes(2); // TODO: Validate checksum?
        }
    }

    static $secret_key_fields = [
        1  => ['d', 'p', 'q', 'u'], // RSA
        2  => ['d', 'p', 'q', 'u'], // RSA-E
        3  => ['d', 'p', 'q', 'u'], // RSA-S
        16 => ['x'],                // ELG-E
        17 => ['x'],                // DSA
    ];

    function key_from_input()
    {
        foreach (self::$secret_key_fields[$this->algorithm] as $field) {
            $this->key[$field] = $this->read_mpi();
        }
    }

    function body()
    {
        $bytes           = parent::body() . chr($this->s2k_useage);
        $secret_material = null;
        if ($this->s2k_useage == 255 || $this->s2k_useage == 254) {
            $bytes .= chr($this->symmetric_algorithm);
            $bytes .= $this->s2k->to_bytes();
        }
        if ($this->s2k_useage > 0) {
            $bytes .= $this->encrypted_data;
        } else {
            $secret_material = '';
            foreach (self::$secret_key_fields[$this->algorithm] as $f) {
                $f               = $this->key[$f];
                $secret_material .= pack('n', Pgp::bitlength($f));
                $secret_material .= $f;
            }
            $bytes .= $secret_material;

            // 2-octet checksum
            $chk = 0;
            for ($i = 0; $i < strlen($secret_material); $i++) {
                $chk = ($chk + ord($secret_material[$i])) % 65536;
            }
            $bytes .= pack('n', $chk);
        }

        return $bytes;
    }
}
