<?php

namespace Alexzvn\SWAToken\Signature;

/**
 * Avaliable algo include: sha1, sha224, sha256, sha384, sha512, ...
 * Using hash_hmac_algos() to get list of avaliable algo
 * @see https://www.php.net/manual/en/function.hash-hmac.php
 */
class AlgoSignatureProvider extends SignatureProvider
{
    public function __construct(
        protected readonly string $secret,
        protected readonly string $algo = 'sha256'
    ) {}

    public function sign(string $data): string
    {
        return base64_encode(hash_hmac($this->algo, $data, $this->secret, true));
    }

    public function verify(string $data, string $signature): bool
    {
        return hash_equals($this->sign($data), $signature);
    }
}
