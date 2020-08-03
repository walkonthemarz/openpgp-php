<?php

namespace OpenPGP;

use IteratorAggregate;
use ArrayAccess;
use ArrayIterator;
use OpenPGP\Packets\Packet;
use OpenPGP\Packets\CompressedData;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Packets\Signature;
use OpenPGP\Packets\PublicSubkey;
use OpenPGP\Packets\SecretSubkey;
use OpenPGP\Packets\PublicKey;
use OpenPGP\Packets\UserID;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-11
 * @see http://tools.ietf.org/html/rfc4880#section-11.3
 */
class Message implements IteratorAggregate, ArrayAccess
{
    public $uri     = null;
    public $packets = [];

    static function parse_file($path)
    {
        if (($msg = self::parse(file_get_contents($path)))) {
            $msg->uri = preg_match('!^[\w\d]+://!', $path) ? $path : 'file://' . realpath($path);

            return $msg;
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-4.1
     * @see http://tools.ietf.org/html/rfc4880#section-4.2
     */
    static function parse($input)
    {
        if (is_resource($input)) {
            return self::parse_stream($input);
        }
        if (is_string($input)) {
            return self::parse_string($input);
        }
    }

    static function parse_stream($input)
    {
        return self::parse_string(stream_get_contents($input));
    }

    static function parse_string($input)
    {
        $msg = new self;
        while (($length = strlen($input)) > 0) {
            if (($packet = Packet::parse($input))) {
                $msg[] = $packet;
            }
            if ($length == strlen($input)) { // is parsing stuck?
                break;
            }
        }

        return $msg;
    }

    function __construct(array $packets = [])
    {
        $this->packets = $packets;
    }

    function to_bytes()
    {
        $bytes = '';
        foreach ($this as $p) {
            $bytes .= $p->to_bytes();
        }

        return $bytes;
    }

    /**
     * Extract signed objects from a well-formatted message
     *
     * Recurses into CompressedDataPacket
     *
     * @see http://tools.ietf.org/html/rfc4880#section-11
     */
    function signatures()
    {
        $msg = $this;
        while ($msg[0] instanceof CompressedData) {
            $msg = $msg[0]->data;
        }

        $key        = null;
        $userid     = null;
        $subkey     = null;
        $sigs       = [];
        $final_sigs = [];

        foreach ($msg as $idx => $p) {
            if ($p instanceof LiteralData) {
                return [[$p, array_values(array_filter($msg->packets, function ($p) {
                    return $p instanceof Signature;
                }))]];
            } elseif ($p instanceof PublicSubkey || $p instanceof SecretSubkey) {
                if ($userid) {
                    array_push($final_sigs, [$key, $userid, $sigs]);
                    $userid = null;
                } elseif ($subkey) {
                    array_push($final_sigs, [$key, $subkey, $sigs]);
                    $key = null;
                }
                $sigs   = [];
                $subkey = $p;
            } elseif ($p instanceof PublicKey) {
                if ($userid) {
                    array_push($final_sigs, [$key, $userid, $sigs]);
                    $userid = null;
                } elseif ($subkey) {
                    array_push($final_sigs, [$key, $subkey, $sigs]);
                    $subkey = null;
                } elseif ($key) {
                    array_push($final_sigs, [$key, $sigs]);
                    $key = null;
                }
                $sigs = [];
                $key  = $p;
            } elseif ($p instanceof UserID) {
                if ($userid) {
                    array_push($final_sigs, [$key, $userid, $sigs]);
                    $userid = null;
                } elseif ($key) {
                    array_push($final_sigs, [$key, $sigs]);
                }
                $sigs   = [];
                $userid = $p;
            } elseif ($p instanceof Signature) {
                $sigs[] = $p;
            }
        }

        if ($userid) {
            array_push($final_sigs, [$key, $userid, $sigs]);
        } elseif ($subkey) {
            array_push($final_sigs, [$key, $subkey, $sigs]);
        } elseif ($key) {
            array_push($final_sigs, [$key, $sigs]);
        }

        return $final_sigs;
    }

    /**
     * Function to extract verified signatures
     * $verifiers is an array of callbacks formatted like array('RSA' => array('SHA256' => CALLBACK)) that take two parameters: raw message and signature packet
     */
    function verified_signatures($verifiers)
    {
        $signed  = $this->signatures();
        $vsigned = [];

        foreach ($signed as $sign) {
            $signatures = array_pop($sign);
            $vsigs      = [];

            foreach ($signatures as $sig) {
                $verifier = $verifiers[$sig->key_algorithm_name()][$sig->hash_algorithm_name()];
                if ($verifier && $this->verify_one($verifier, $sign, $sig)) {
                    $vsigs[] = $sig;
                }
            }
            array_push($sign, $vsigs);
            $vsigned[] = $sign;
        }

        return $vsigned;
    }

    function verify_one($verifier, $sign, $sig)
    {
        if ($sign[0] instanceof LiteralData) {
            $sign[0]->normalize();
            $raw = $sign[0]->data;
        } elseif (isset($sign[1]) && $sign[1] instanceof UserID) {
            $raw = implode('', array_merge($sign[0]->fingerprint_material(), [chr(0xB4),
                                                                              pack('N', strlen($sign[1]->body())), $sign[1]->body()]));
        } elseif (isset($sign[1]) && ($sign[1] instanceof PublicSubkey || $sign[1] instanceof SecretSubkey)) {
            $raw = implode('', array_merge($sign[0]->fingerprint_material(), $sign[1]->fingerprint_material()));
        } elseif ($sign[0] instanceof PublicKey) {
            $raw = implode('', $sign[0]->fingerprint_material());
        } else {
            return null;
        }

        return call_user_func($verifier, $raw . $sig->trailer, $sig);
    }

    // IteratorAggregate interface

    function getIterator()
    {
        return new ArrayIterator($this->packets);
    }

    // ArrayAccess interface

    function offsetExists($offset)
    {
        return isset($this->packets[$offset]);
    }

    function offsetGet($offset)
    {
        return $this->packets[$offset];
    }

    function offsetSet($offset, $value)
    {
        return is_null($offset) ? $this->packets[] = $value : $this->packets[$offset] = $value;
    }

    function offsetUnset($offset)
    {
        unset($this->packets[$offset]);
    }
}

