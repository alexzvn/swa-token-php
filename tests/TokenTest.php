<?php

namespace Tests;

use Alexzvn\SWAToken\Token\SignedToken;
use Alexzvn\SWAToken\Token\Token;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    public function testTokenCreateWithMissingParam()
    {
        $this->assertInstanceOf(Token::class,
            new Token('swat', 'sha256', 'issuer', 'subject', time(), time() + 3600)
        );
    }

    public function testTokenCreateNotAllowColonOrDot()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Param can not contain colon or dot');

        new Token('swat', 'sha256', 'issuer:with:colon', 'subject.dot', time(), time() + 3600);
    }

    public function testSignedTokenAllowAnyCharacter()
    {
        $token =  new Token('swat', 'sha256', 'issuer', 'subject', time(), time() + 3600);
        $signedToken = SignedToken::from($token, 'signature!@#$%^&*()_+:.');

        $this->assertInstanceOf(SignedToken::class, $signedToken);
    }
}
