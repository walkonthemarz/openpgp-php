<?php

namespace OpenPGP\Crypt;

// From http://phpseclib.sourceforge.net/
use phpseclib\Crypt\RSA as Crypt_RSA;
use phpseclib\Math\BigInteger as Math_BigInteger;
use OpenPGP\Message;
use OpenPGP\Packets\PublicKey;
use ArrayAccess;
use OpenPGP\Packets\LiteralData;
use OpenPGP\Packets\SecretKey;
use OpenPGP\Packets\Signature;
use OpenPGP\Packets\Signatures\Issuer;
use OpenPGP\Packets\Signatures\KeyFlags;
use OpenPGP\Packets\AsymmetricSessionKey;

class RSA
{
    const CRYPT_RSA_ENCRYPTION_PKCS1 = Crypt_RSA::ENCRYPTION_PKCS1;
    const CRYPT_RSA_SIGNATURE_PKCS1  = Crypt_RSA::SIGNATURE_PKCS1;

    protected $key;
    protected $message;

    // Construct a wrapper object from a key or a message packet
    function __construct($packet)
    {
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }
        if ($packet instanceof PublicKey || $packet[0] instanceof PublicKey) { // If it's a key (other keys are subclasses of this one)
            $this->key = $packet;
        } else {
            $this->message = $packet;
        }
    }

    function key($keyid = null)
    {
        if (!$this->key) {
            return null;
        } // No key
        if ($this->key instanceof Message) {
            foreach ($this->key as $p) {
                if ($p instanceof PublicKey) {
                    if (!$keyid || strtoupper(substr($p->fingerprint, strlen($keyid) * -1)) == strtoupper($keyid)) {
                        return $p;
                    }
                }
            }
        }

        return $this->key;
    }

    // Get Crypt_RSA for the public key
    function public_key($keyid = null)
    {
        return self::convert_public_key($this->key($keyid));
    }

    // Get Crypt_RSA for the private key
    function private_key($keyid = null)
    {
        return self::convert_private_key($this->key($keyid));
    }

    // Pass a message to verify with this key, or a key (OpenPGP or Crypt_RSA) to check this message with
    // Second optional parameter to specify which signature to verify (if there is more than one)
    function verify($packet)
    {
        $self = $this; // For old PHP
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }
        if (!$this->message) {
            $m        = $packet;
            $verifier = function ($m, $s) use ($self) {
                $key = $self->public_key($s->issuer());
                if (!$key) {
                    return false;
                }
                $key->setHash(strtolower($s->hash_algorithm_name()));

                return $key->verify($m, reset($s->data));
            };
        } else {
            if (!($packet instanceof Crypt_RSA)) {
                $packet = new self($packet);
            }

            $m        = $this->message;
            $verifier = function ($m, $s) use ($self, $packet) {
                if (!($packet instanceof Crypt_RSA)) {
                    $key = $packet->public_key($s->issuer());
                }
                if (!$key) {
                    return false;
                }
                $key->setHash(strtolower($s->hash_algorithm_name()));

                return $key->verify($m, reset($s->data));
            };
        }

        return $m->verified_signatures(['RSA' => [
            'MD5'    => $verifier,
            'SHA1'   => $verifier,
            'SHA224' => $verifier,
            'SHA256' => $verifier,
            'SHA384' => $verifier,
            'SHA512' => $verifier,
        ]]);
    }

    // Pass a message to sign with this key, or a secret key to sign this message with
    // Second parameter is hash algorithm to use (default SHA256)
    // Third parameter is the 16-digit key ID to use... defaults to the key id in the key packet
    function sign($packet, $hash = 'SHA256', $keyid = null)
    {
        if (!is_object($packet)) {
            if ($this->key) {
                $packet = new LiteralData($packet);
            } else {
                $packet = Message::parse($packet);
            }
        }

        if ($packet instanceof SecretKey || $packet instanceof Crypt_RSA
            || ($packet instanceof ArrayAccess && $packet[0] instanceof SecretKey)) {
            $key     = $packet;
            $message = $this->message;
        } else {
            $key     = $this->key;
            $message = $packet;
        }

        if (!$key || !$message) {
            return null;
        } // Missing some data

        if ($message instanceof Message) {
            $sign    = $message->signatures();
            $message = $sign[0][0];
        }

        if (!($key instanceof Crypt_RSA)) {
            $key = new self($key);
            if (!$keyid) {
                $keyid = substr($key->key()->fingerprint, -16, 16);
            }
            $key = $key->private_key($keyid);
        }
        $key->setHash(strtolower($hash));

        $sig                      = new Signature($message, 'RSA', strtoupper($hash));
        $sig->hashed_subpackets[] = new Issuer($keyid);
        $sig->sign_data(['RSA' => [$hash => function ($data) use ($key) {
            return [$key->sign($data)];
        }]]);

        return new Message([$sig, $message]);
    }

    /** Pass a message with a key and userid packet to sign */
    // TODO: merge this with the normal sign function
    function sign_key_userid($packet, $hash = 'SHA256', $keyid = null)
    {
        if (is_array($packet)) {
            $packet = new Message($packet);
        } elseif (!is_object($packet)) {
            $packet = Message::parse($packet);
        }

        $key = $this->private_key($keyid);
        if (!$key || !$packet) {
            return null;
        } // Missing some data

        if (!$keyid) {
            $keyid = substr($this->key->fingerprint, -16);
        }
        $key->setHash(strtolower($hash));

        $sig = null;
        foreach ($packet as $p) {
            if ($p instanceof Signature) {
                $sig = $p;
            }
        }
        if (!$sig) {
            $sig                      = new Signature($packet, 'RSA', strtoupper($hash));
            $sig->signature_type      = 0x13;
            $sig->hashed_subpackets[] = new KeyFlags([0x01 | 0x02]);
            $sig->hashed_subpackets[] = new Issuer($keyid);
            $packet[]                 = $sig;
        }

        $sig->sign_data(['RSA' => [$hash => function ($data) use ($key) {
            return [$key->sign($data)];
        }]]);

        return $packet;
    }

    function decrypt($packet)
    {
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }

        if ($packet instanceof SecretKey || $packet instanceof Crypt_RSA
            || ($packet instanceof ArrayAccess && $packet[0] instanceof SecretKey)) {
            $keys    = $packet;
            $message = $this->message;
        } else {
            $keys    = $this->key;
            $message = $packet;
        }

        if (!$keys || !$message) {
            return null;
        } // Missing some data

        if (!($keys instanceof Crypt_RSA)) {
            $keys = new self($keys);
        }

        foreach ($message as $p) {
            if ($p instanceof AsymmetricSessionKey) {
                if ($keys instanceof Crypt_RSA) {
                    $sk = self::try_decrypt_session($keys, substr($p->encrypted_data, 2));
                } elseif (strlen(str_replace('0', '', $p->keyid)) < 1) {
                    foreach ($keys->key as $k) {
                        $sk = self::try_decrypt_session(self::convert_private_key($k), substr($p->encrypted_data, 2));
                        if ($sk) {
                            break;
                        }
                    }
                } else {
                    $key = $keys->private_key($p->keyid);
                    $sk  = self::try_decrypt_session($key, substr($p->encrypted_data, 2));
                }

                if (!$sk) {
                    continue;
                }

                $r = Symmetric::decryptPacket(Symmetric::getEncryptedData($message), $sk[0], $sk[1]);
                if ($r) {
                    return $r;
                }
            }
        }

        return null; /* Failed */
    }

    static function try_decrypt_session($key, $edata)
    {
        $key->setEncryptionMode(self::CRYPT_RSA_ENCRYPTION_PKCS1);
        $data = @$key->decrypt($edata);
        if (!$data) {
            return null;
        }
        $sk  = substr($data, 1, strlen($data) - 3);
        $chk = unpack('n', substr($data, -2));
        $chk = reset($chk);

        $sk_chk = 0;
        for ($i = 0; $i < strlen($sk); $i++) {
            $sk_chk = ($sk_chk + ord($sk[$i])) % 65536;
        }

        if ($sk_chk != $chk) {
            return null;
        }

        return [ord($data[0]), $sk];
    }

    static function crypt_rsa_key($mod, $exp, $hash = 'SHA256')
    {
        $rsa = new Crypt_RSA();
        $rsa->setSignatureMode(self::CRYPT_RSA_SIGNATURE_PKCS1);
        $rsa->setHash(strtolower($hash));
        $rsa->modulus  = new Math_BigInteger($mod, 256);
        $rsa->k        = strlen($rsa->modulus->toBytes());
        $rsa->exponent = new Math_BigInteger($exp, 256);
        $rsa->setPublicKey();

        return $rsa;
    }

    static function convert_key($packet, $private = false)
    {
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }
        if ($packet instanceof Message) {
            $packet = $packet[0];
        }

        $mod = $packet->key['n'];
        $exp = $packet->key['e'];
        if ($private) {
            $exp = $packet->key['d'];
        }
        if (!$exp) {
            return null;
        } // Packet doesn't have needed data

        $rsa = self::crypt_rsa_key($mod, $exp);

        if ($private) {
            /**
             * @see https://github.com/phpseclib/phpseclib/issues/1113
             * Primes and coefficients now use BigIntegers.
             **/
            //set the primes
            if ($packet->key['p'] && $packet->key['q']) {
                $rsa->primes = [
                    1 => new Math_BigInteger($packet->key['p'], 256),
                    2 => new Math_BigInteger($packet->key['q'], 256),
                ];
            }
            // set the coefficients
            if ($packet->key['u']) {
                $rsa->coefficients = [2 => new Math_BigInteger($packet->key['u'], 256)];
            }
        }

        return $rsa;
    }

    static function convert_public_key($packet)
    {
        return self::convert_key($packet, false);
    }

    static function convert_private_key($packet)
    {
        return self::convert_key($packet, true);
    }

}
