<?php

namespace Alexzvn\SWAToken\Signature;

abstract class SignatureProvider
{
    public function __construct(
        protected readonly string $secret
    ) {}

    abstract public function sign(string $token): string;

    abstract public function verify(string $token, string $signature): bool;
}
