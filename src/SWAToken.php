<?php

namespace Alexzvn\SWAToken;

use Alexzvn\SWAToken\Exception\ProviderAlgoMissingException;
use Alexzvn\SWAToken\Signature\AlgoSignatureProvider as Provider;
use Alexzvn\SWAToken\Signature\SignatureProvider;
use Alexzvn\SWAToken\Token\SignedToken;
use Alexzvn\SWAToken\Token\Token;

final class SWAToken {
    protected array $providers = [];

    protected const NAME = "swat";

    public function __construct(protected string $algo, SignatureProvider $provider) {
        $this->providers[$algo] = $provider;
    }

    /**
     * Create a new token
     * 
     * @param string $issuer It can be user id, email, username, ...
     * @param string|null $subject It determine what this token is used for
     * @param int|null $ttl Time to live in seconds
     * @return \Alexzvn\SWAToken\Token\SignedToken
     */
    public function create(string $issuer, ?string $subject = '', ?int $ttl = null): SignedToken
    {
        $token = new Token(
            static::NAME,
            $this->algo,
            $issuer,
            $subject,
            time(),
            $ttl ? time() + $ttl : null,
        );

        /**
         * @var \Alexzvn\SWAToken\Signature\SignatureProvider $provider
         */
        $provider = $this->providers[$this->algo];
        $signature = $provider->sign($token->getToken());

        return SignedToken::from($token, $signature);
    }

    /**
     * Verify token is created by
     * 
     * @throws \Alexzvn\SWAToken\Exception\ProviderAlgoMissingException throws when algorithm in token is not registered
     * 
     * @param string $token
     * @return bool
     */
    public function verify(string $token)
    {
        if (! SignedToken::validate($token)) {
            return false;
        }

        $token = SignedToken::parse($token);

        if (! $token instanceof SignedToken) {
            return false;
        }

        /**
         * @var \Alexzvn\SWAToken\Signature\SignatureProvider $provider
         */
        $provider = $this->providers[$token->algo] ?? null;

        if (! $provider) {
            throw new ProviderAlgoMissingException("Provider for algo {$token->algo} not found");
        }

        if (! $provider->verify($token->getToken(), $token->signature)) {
            echo 'hm...';
            return false;
        }

        if ($token->expire_at) {
            return $token->expire_at > time();
        }

        return true;
    }

    /**
     * Parse token string to Token object
     * 
     * @param string $token
     * @return \Alexzvn\SWAToken\Token\SignedToken|\Alexzvn\SWAToken\Token\Token|null
     */
    public function parse(string $token): ?Token
    {
        if (! SignedToken::validate($token)) {
            return null;
        }

        return SignedToken::parse($token);
    }

    /**
     * Get current signature provider
     * 
     * @return \Alexzvn\SWAToken\Signature\SignatureProvider
     */
    public function getSigner(): SignatureProvider
    {
        return $this->providers[$this->algo];
    }

    /**
     * Change current signature provider
     * 
     * @param string $algo Algorithm name already registered
     * @param \Alexzvn\SWAToken\Signature\SignatureProvider|null $provider
     */
    public function use(string $algo, ?SignatureProvider $provider = null)
    {
        if (isset($provider)) {
            $this->providers[$algo] = $provider;
        }

        if (!isset($this->providers[$algo])) {
            throw new ProviderAlgoMissingException("Provider for $algo not found");
        }

        $this->algo = $algo;
    }

    /**
     * Register a new signature provider
     * 
     * @param string $algo Algorithm name
     * @param \Alexzvn\SWAToken\Signature\SignatureProvider $provider
     */
    public function register(string $algo, SignatureProvider $provider)
    {
        $this->providers[$algo] = $provider;
    }

    public static function createWithDefaultProviders(string $secret) {
        $default = [
            'HS1' => new Provider($secret, 'sha1'),
            'HS256' => new Provider($secret, 'sha256'),
            'HS384' => new Provider($secret, 'sha384'),
            'HS512' => new Provider($secret, 'sha512'),
        ];

        $swat = new static('HS256', $default['HS256']);

        foreach ($default as $algo => $provider) {
            $swat->register($algo, $provider);
        }

        return $swat;
    }
}
