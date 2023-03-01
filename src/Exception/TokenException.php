<?php

namespace Nails\MFA\Exception;

use Nails\Auth\Exception\AuthException;
use Nails\MFA\Resource\Token;
use Nails\Auth\Resource\User;

class TokenException extends MfaException
{
    protected ?Token $token = null;

    // --------------------------------------------------------------------------

    public function setToken(?Token $token): self
    {
        $this->token = $token;
        return $this;
    }

    // --------------------------------------------------------------------------

    public function getToken(): ?Token
    {
        return $this->token;
    }
}
