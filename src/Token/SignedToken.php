<?php

namespace Alexzvn\SWAToken\Token;

class SignedToken extends Token
{
    public function __construct(
        string $name,
        string $algo,
        ?string $issuer,
        ?string $subject,
        ?int $issued_at,
        ?int $expire_at,
        public readonly string $signature,
    ) {
        parent::__construct($name, $algo, $issuer, $subject, $issued_at, $expire_at);
    }

    public static function from(Token $token, string $signature)
    {
        return new static(
            $token->name,
            $token->algo,
            $token->issuer,
            $token->subject,
            $token->issued_at,
            $token->expire_at,
            $signature,
        );
    }

    public function getSignedToken()
    {
        return sprintf('%s.%s', $this->getToken(), $this->signature);
    }

    public function __toString()
    {
        return $this->getSignedToken();
    }
}
