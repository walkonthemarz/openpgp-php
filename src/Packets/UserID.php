<?php

namespace OpenPGP\Packets;

/**
 * OpenPGP User ID packet (tag 13).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.11
 * @see http://tools.ietf.org/html/rfc2822
 */
class UserID extends Packet
{
    public $name, $comment, $email;

    function __construct($name = '', $comment = '', $email = '')
    {
        parent::__construct();
        if (!$comment && !$email) {
            $this->input = $name;
            $this->read();
        } else {
            $this->name    = $name;
            $this->comment = $comment;
            $this->email   = $email;
        }
    }

    function read()
    {
        $this->data = $this->input;
        // User IDs of the form: "name (comment) <email>"
        if (preg_match('/^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/', $this->data, $matches)) {
            $this->name    = trim($matches[1]);
            $this->comment = trim($matches[2]);
            $this->email   = trim($matches[3]);
        } // User IDs of the form: "name <email>"
        elseif (preg_match('/^([^<]+)\s+<([^>]+)>$/', $this->data, $matches)) {
            $this->name    = trim($matches[1]);
            $this->comment = null;
            $this->email   = trim($matches[2]);
        } // User IDs of the form: "name"
        elseif (preg_match('/^([^<]+)$/', $this->data, $matches)) {
            $this->name    = trim($matches[1]);
            $this->comment = null;
            $this->email   = null;
        } // User IDs of the form: "<email>"
        elseif (preg_match('/^<([^>]+)>$/', $this->data, $matches)) {
            $this->name    = null;
            $this->comment = null;
            $this->email   = trim($matches[2]);
        }
    }

    function __toString()
    {
        $text = [];
        if ($this->name) {
            $text[] = $this->name;
        }
        if ($this->comment) {
            $text[] = "({$this->comment})";
        }
        if ($this->email) {
            $text[] = "<{$this->email}>";
        }

        return implode(' ', $text);
    }

    function body()
    {
        return '' . $this; // Convert to string is the body
    }
}
