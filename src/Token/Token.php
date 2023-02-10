<?php

namespace Alexzvn\SWAToken\Token;

use Alexzvn\SWAToken\Exception\InvalidTokenFormatException;
use InvalidArgumentException;

class Token {
    public const DISCOVER = '/swat:([^.:]*)\\.([^.:]*):([^.:]*):([0-9]{10,12}):([0-9]{0,12})\\.?(.*)$/';

    public function __construct(
        public readonly string $name,
        public readonly string $algo,
        public readonly ?string $issuer,
        public readonly ?string $subject,
        public readonly ?int $issued_at,
        public readonly ?int $expire_at,
    ) {
        $this->check($this->name);
        $this->check($this->algo);
        $this->check($this->issuer);
        $this->check($this->subject);
    }

    public function getToken() {
        $head = sprintf('%s:%s', $this->name, $this->algo);
        $payload = sprintf('%s:%s:%s:%s', $this->issuer, $this->subject, $this->issued_at, $this->expire_at);

        return sprintf('%s.%s', $head, $payload);
    }

    public static function validate(string $token) {
        return preg_match(self::DISCOVER, $token);
    }

    public static function parse(string $token) {
        if (! static::validate($token)) {
            throw new InvalidTokenFormatException('Invalid token format');
        }

        preg_match(self::DISCOVER, $token, $matches);

        [, $algo, $issuer, $subject, $issued_at, $expire_at] = $matches;
        $signature = $matches[6] ?? null;

        $token = new self('swat', $algo, $issuer, $subject, (int) $issued_at, $expire_at ? (int) $expire_at : null);

        return $signature ? SignedToken::from($token, $signature) : $token;
    }

    protected function check($value)
    {
        if (str_contains($value, ':')) {
            throw new InvalidArgumentException('Param can not contain colon or dot');
        }
    }

    public function __toString()
    {
        return $this->getToken();
    }
}
