<?php

namespace Tests;

use Alexzvn\SWAToken\Exception\ProviderAlgoMissingException;
use Alexzvn\SWAToken\Signature\AlgoSignatureProvider;
use Alexzvn\SWAToken\SWAToken;
use PHPUnit\Framework\TestCase;

final class SwatTest extends TestCase
{
    protected SWAToken $swat;
    protected SWAToken $swat2;

    public function __construct($name)
    {
        parent::__construct($name);

        $this->swat = new SWAToken(
            'HS256', new AlgoSignatureProvider('secret')
        );

        $this->swat2 = SWAToken::createWithDefaultProviders('secret-2');
    }

    public function testCreateTokenWithFullData()
    {
        $token = $this->swat->create('alexzvn', 'user|premium', 3600);

        $this->assertTrue($this->swat->verify($token), 'Token should be valid');
        $this->assertNotTrue($this->swat2->verify($token), 'Token should be invalid because it is signed with different secret');

        $token = $this->swat->create('alexzvn', 'user|gold');

        $this->assertTrue($this->swat->verify($token), 'Token should be valid because it has no expiration time');
        $this->assertNotTrue($this->swat2->verify($token));
    }

    public function testCreateTokenWithMissingData()
    {
        $token = $this->swat->create('1');

        $this->assertTrue($this->swat->verify($token), 'Token should be valid although it has no subject');
    }

    public function testCreateTokenWithExpiredDate()
    {
        $token = $this->swat->create('alexzvn', 'user|premium', -1);

        $this->assertFalse($this->swat->verify($token), 'Token should be invalid because it is expired');
    }

    public function testVerifyTokenWithMissingAlgorithm()
    {
        $this->expectException(ProviderAlgoMissingException::class);

        $this->swat2->use('HS512');

        $token = $this->swat2->create('alexzvn', 'user|premium', 3600);

        $this->swat->verify($token);
    }

    public function testVerifyTokenWithInvalidSignature()
    {
        $token = $this->swat->create('alexzvn', 'user|premium', 3600);

        $this->assertFalse($this->swat->verify($token . 'invalid'));
    }
}
