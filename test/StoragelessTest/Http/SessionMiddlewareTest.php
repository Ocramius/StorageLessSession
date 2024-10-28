<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

declare(strict_types=1);

namespace PSR7SessionsTest\Storageless\Http;

use DateTime;
use DateTimeImmutable;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\SetCookie;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration as JwtConfig;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration as FingerprintConfig;
use PSR7Sessions\Storageless\Http\ClientFingerprint\SameOriginRequest;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Source;
use PSR7Sessions\Storageless\Http\Configuration;
use PSR7Sessions\Storageless\Http\SessionMiddleware;
use PSR7Sessions\Storageless\Session\DefaultSessionData;
use PSR7Sessions\Storageless\Session\SessionInterface;

use function assert;
use function base64_encode;
use function random_bytes;
use function random_int;
use function time;
use function uniqid;

#[CoversClass(SessionMiddleware::class)]
final class SessionMiddlewareTest extends TestCase
{
    private Configuration $config;
    private SessionMiddleware $middleware;

    protected function setUp(): void
    {
        $this->config     = new Configuration(JwtConfig::forSymmetricSigner(
            new Sha256(),
            $this->makeRandomSymmetricKey(),
        ));
        $this->middleware = new SessionMiddleware($this->config);
    }

    public function testSkipsInjectingSessionCookieOnEmptyContainer(): void
    {
        $response = $this->ensureSameResponse($this->middleware, new ServerRequest(), $this->emptyValidationMiddleware());

        self::assertNull($this->getCookie($response)->getValue());
    }

    public function testInjectsSessionInResponseCookies(): void
    {
        $initialResponse = new Response();
        $response        = $this->middleware->process(new ServerRequest(), $this->writingMiddleware());

        self::assertNotSame($initialResponse, $response);
        self::assertEmpty($this->getCookie($response, 'non-existing')->getValue());

        $token = $this->getCookie($response)->getValue();

        self::assertIsString($token);
        self::assertTrue($token !== '');
        $parsedToken = (new Parser(new JoseEncoder()))->parse($token);
        self::assertInstanceOf(Plain::class, $parsedToken);
        self::assertEquals(['foo' => 'bar'], $parsedToken->claims()->get('session-data'));
    }

    public function testSessionContainerCanBeReusedOverMultipleRequests(): void
    {
        $sessionValue = uniqid('', true);

        $checkingMiddleware = $this->fakeDelegate(
            static function (ServerRequestInterface $request) use ($sessionValue) {
                $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
                assert($session instanceof SessionInterface);

                self::assertSame($sessionValue, $session->get('foo'));
                self::assertFalse($session->hasChanged());

                $session->set('foo', $sessionValue . 'changed');

                self::assertTrue(
                    $session->hasChanged(),
                    'ensuring that the cookie is sent again: '
                    . 'non-modified session containers are not to be re-serialized into a token',
                );

                return new Response();
            },
        );

        $firstResponse = $this->middleware->process(new ServerRequest(), $this->writingMiddleware($sessionValue));

        $response = $this->middleware->process(
            $this->requestWithResponseCookies($firstResponse),
            $checkingMiddleware,
        );

        self::assertNotSame($response, $firstResponse);
    }

    public function testSessionContainerCanBeCreatedEvenIfTokenDataIsMalformed(): void
    {
        $sessionValue = uniqid('not valid session data', true);

        $checkingMiddleware = $this->fakeDelegate(
            static function (ServerRequestInterface $request) use ($sessionValue) {
                $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
                assert($session instanceof SessionInterface);

                self::assertSame($sessionValue, $session->get('scalar'));
                self::assertFalse($session->hasChanged());

                return new Response();
            },
        );

        $this->middleware->process(
            (new ServerRequest())
                ->withCookieParams([
                    $this->config->getCookie()->getName() => $this->createTokenWithCustomClaim(
                        $this->config,
                        new DateTimeImmutable('-1 day'),
                        new DateTimeImmutable('+1 day'),
                        $sessionValue,
                    ),
                ]),
            $checkingMiddleware,
        );
    }

    public function testWillIgnoreRequestsWithExpiredTokens(): void
    {
        $expiredToken = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $this->createToken(
                    $this->config,
                    new DateTimeImmutable('-1 day'),
                    new DateTimeImmutable('-2 day'),
                ),
            ]);

        $this->ensureSameResponse($this->middleware, $expiredToken, $this->emptyValidationMiddleware());
    }

    public function testWillIgnoreRequestsWithNonPlainTokens(): void
    {
        $unknownTokenType = $this->createMock(Token::class);
        $fakeParser       = $this->createMock(ParserInterface::class);
        $jwtConfiguration = JwtConfig::forSymmetricSigner(
            new Sha256(),
            self::makeRandomSymmetricKey(),
        );

        $fakeParser->expects(self::atLeastOnce())
            ->method('parse')
            ->with('THE_COOKIE')
            ->willReturn($unknownTokenType);
        $jwtConfiguration->setParser($fakeParser);

        $this->ensureSameResponse(
            new SessionMiddleware(
                $this->config
                    ->withJwtConfiguration($jwtConfiguration)
                    ->withCookie(SetCookie::create('COOKIE_NAME')),
            ),
            (new ServerRequest())
                ->withCookieParams(['COOKIE_NAME' => 'THE_COOKIE']),
            $this->emptyValidationMiddleware(),
        );
    }

    public function testWillIgnoreRequestsWithTokensFromFuture(): void
    {
        $tokenInFuture = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $this->createToken(
                    $this->config,
                    new DateTimeImmutable('+1 day'),
                    new DateTimeImmutable('-2 day'),
                ),
            ]);

        $this->ensureSameResponse($this->middleware, $tokenInFuture, $this->emptyValidationMiddleware());
    }

    public function testWillIgnoreUnSignedTokens(): void
    {
        $jwtConfiguration = JwtConfig::forSymmetricSigner(
            new Sha256(),
            self::makeRandomSymmetricKey(),
        );
        $unsignedToken    = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $jwtConfiguration->builder()
                    ->issuedAt(new DateTimeImmutable('-1 day'))
                    ->canOnlyBeUsedAfter(new DateTimeImmutable('-1 day'))
                    ->expiresAt(new DateTimeImmutable('+1 day'))
                    ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
                    ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
                    ->toString(),
            ]);

        $this->ensureSameResponse($this->middleware, $unsignedToken, $this->emptyValidationMiddleware());
    }

    public function testWillIgnoreSignedTokensWithoutIssuedAt(): void
    {
        $jwtConfiguration = $this->config->getJwtConfiguration();
        $unsignedToken    = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $jwtConfiguration->builder()
                    ->canOnlyBeUsedAfter(new DateTimeImmutable('-1 day'))
                    ->expiresAt(new DateTimeImmutable('+1 day'))
                    ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
                    ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
                    ->toString(),
            ]);

        $this->ensureSameResponse($this->middleware, $unsignedToken, $this->emptyValidationMiddleware());
    }

    public function testWillIgnoreRequestsWithEmptyStringCookie(): void
    {
        $expiredToken = (new ServerRequest())
            ->withCookieParams([$this->config->getCookie()->getName() => '']);

        $this->ensureSameResponse($this->middleware, $expiredToken, $this->emptyValidationMiddleware());
    }

    public function testWillRefreshTokenWithIssuedAtExactlyAtTokenRefreshTimeThreshold(): void
    {
        // forcing ourselves to think of time as a mutable value:
        $time  = time() + random_int(-100, +100);
        $now   = new DateTimeImmutable('@' . $time);
        $clock = new FrozenClock($now);

        $middleware = new SessionMiddleware(
            $this->config
                ->withClock($clock),
            //                ->withIdleTimeout(1000)
            //                ->withRefreshTime(100)
        );

        $jwtConfiguration                = $this->config->getJwtConfiguration();
        $requestWithTokenIssuedInThePast = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $jwtConfiguration->builder()
                    ->expiresAt(new DateTimeImmutable('@' . ($time + 10000)))
                    ->issuedAt(new DateTimeImmutable('@' . ($time - 100)))
                    ->canOnlyBeUsedAfter(new DateTimeImmutable('@' . ($time - 100)))
                    ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
                    ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
                    ->toString(),
            ]);

        $tokenString = $this
            ->getCookie($middleware->process($requestWithTokenIssuedInThePast, $this->fakeDelegate(static function () {
                return new Response();
            })))
            ->getValue();

        self::assertIsString($tokenString);
        self::assertTrue($tokenString !== '');
        $token = (new Parser(new JoseEncoder()))->parse($tokenString);
        self::assertInstanceOf(Plain::class, $token);
        self::assertEquals($now, $token->claims()->get(RegisteredClaims::ISSUED_AT), 'Token was refreshed');
    }

    public function testWillNotRefreshATokenForARequestWithNoGivenTokenAndNoSessionModification(): void
    {
        self::assertNull(
            $this
                ->getCookie($this->middleware->process(
                    (new ServerRequest())
                        ->withCookieParams([$this->config->getCookie()->getName() => 'invalid-token']),
                    $this->fakeDelegate(static fn (): ResponseInterface => new Response()),
                ))
                ->getValue(),
            'No session cookie was set, since session data was not changed, and the token was not valid',
        );
    }

    public function testWillSkipInjectingSessionCookiesWhenSessionIsNotChanged(): void
    {
        $this->ensureSameResponse(
            $this->middleware,
            $this->requestWithResponseCookies(
                $this->middleware->process(new ServerRequest(), $this->writingMiddleware()),
            ),
            $this->fakeDelegate(
                static function (ServerRequestInterface $request) {
                    $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
                    assert($session instanceof SessionInterface);

                    // note: we set the same data just to make sure that we are indeed interacting with the session
                    $session->set('foo', 'bar');

                    self::assertFalse($session->hasChanged());

                    return new Response();
                },
            ),
        );
    }

    public function testWillSendExpirationCookieWhenSessionContentsAreCleared(): void
    {
        $this->ensureClearsSessionCookie(
            $this->middleware,
            $this->requestWithResponseCookies(
                $this->middleware->process(new ServerRequest(), $this->writingMiddleware()),
            ),
            $this->fakeDelegate(
                static function (ServerRequestInterface $request) {
                    $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
                    assert($session instanceof SessionInterface);

                    $session->clear();

                    return new Response();
                },
            ),
        );
    }

    public function testWillIgnoreMalformedTokens(): void
    {
        $this->ensureSameResponse(
            $this->middleware,
            (new ServerRequest())->withCookieParams([$this->config->getCookie()->getName() => 'malformed content']),
            $this->emptyValidationMiddleware(),
        );
    }

    public function testRejectsTokensWithInvalidSignature(): void
    {
        $middlewareWithAlteredKey = new SessionMiddleware(
            $this->config->withJwtConfiguration(
                JwtConfig::forSymmetricSigner(
                    new Sha256(),
                    self::makeRandomSymmetricKey(),
                ),
            ),
        );

        $this->ensureSameResponse(
            $middlewareWithAlteredKey,
            $this->requestWithResponseCookies(
                $this->middleware->process(new ServerRequest(), $this->writingMiddleware()),
            ),
            $this->emptyValidationMiddleware(),
        );
    }

    public function testAllowsModifyingCookieDetails(): void
    {
        $defaultCookie = SetCookie::create('a-different-cookie-name')
            ->withDomain('foo.bar')
            ->withPath('/yadda')
            ->withHttpOnly(false)
            ->withMaxAge(123123)
            ->withValue('a-random-value');

        $dateTime   = new DateTimeImmutable();
        $middleware = new SessionMiddleware(
            $this->config
                ->withCookie($defaultCookie)
                ->withIdleTimeout(123456),
        );

        $response = $middleware->process(new ServerRequest(), $this->writingMiddleware());

        self::assertNull($this->getCookie($response)->getValue());

        $tokenCookie = $this->getCookie($response, 'a-different-cookie-name');

        self::assertNotEmpty($tokenCookie->getValue());
        self::assertNotSame($defaultCookie->getValue(), $tokenCookie->getValue());
        self::assertSame($defaultCookie->getDomain(), $tokenCookie->getDomain());
        self::assertSame($defaultCookie->getPath(), $tokenCookie->getPath());
        self::assertSame($defaultCookie->getHttpOnly(), $tokenCookie->getHttpOnly());
        self::assertSame($defaultCookie->getMaxAge(), $tokenCookie->getMaxAge());
        self::assertEquals($dateTime->getTimestamp() + 123456, $tokenCookie->getExpires());
    }

    public function testSessionTokenParsingIsDelayedWhenSessionIsNotBeingUsed(): void
    {
        $key    = self::makeRandomSymmetricKey();
        $signer = $this->createMock(Signer::class);

        $signer->expects(self::never())->method('verify');
        $signer->method('algorithmId')->willReturn('HS256');

        $middleware                = new SessionMiddleware(
            $this->config->withJwtConfiguration(
                JwtConfig::forSymmetricSigner(
                    $signer,
                    $key,
                ),
            ),
        );
        $jwtConfigurationForBuiler = JwtConfig::forSymmetricSigner(
            new Sha256(),
            $key,
        );
        $request                   = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $jwtConfigurationForBuiler->builder()
                    ->issuedAt(new DateTimeImmutable())
                    ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
                    ->getToken($jwtConfigurationForBuiler->signer(), $jwtConfigurationForBuiler->signingKey())
                    ->toString(),
            ]);

        $middleware->process(
            $request,
            $this->fakeDelegate(static function (ServerRequestInterface $request) {
                self::assertInstanceOf(
                    SessionInterface::class,
                    $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE),
                );

                return new Response();
            }),
        );
    }

    public function testShouldRegenerateTokenWhenRequestHasATokenThatIsAboutToExpire(): void
    {
        $dateTime   = new DateTimeImmutable();
        $middleware = new SessionMiddleware(
            $this->config
                ->withClock(new FrozenClock($dateTime))
                ->withIdleTimeout(1000)
                ->withRefreshTime(300),
        );

        $jwtConfiguration = $this->config->getJwtConfiguration();
        $expiringToken    = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $jwtConfiguration->builder()
                    ->issuedAt(new DateTimeImmutable('-800 second'))
                    ->canOnlyBeUsedAfter(new DateTimeImmutable('-800 second'))
                    ->expiresAt(new DateTimeImmutable('+200 second'))
                    ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
                    ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
                    ->toString(),
            ]);

        $initialResponse = new Response();

        $response = $middleware->process($expiringToken, $this->fakeDelegate(static function () use ($initialResponse) {
            return $initialResponse;
        }));

        self::assertNotSame($initialResponse, $response);

        $tokenCookie = $this->getCookie($response);

        self::assertNotEmpty($tokenCookie->getValue());
        self::assertEquals($dateTime->getTimestamp() + 1000, $tokenCookie->getExpires());
    }

    public function testShouldNotRegenerateTokenWhenRequestHasATokenThatIsFarFromExpiration(): void
    {
        $middleware = new SessionMiddleware(
            $this->config
                ->withIdleTimeout(1000)
                ->withRefreshTime(300),
        );

        $jwtConfiguration = $this->config->getJwtConfiguration();
        $validToken       = (new ServerRequest())
            ->withCookieParams([
                $this->config->getCookie()->getName() => $jwtConfiguration->builder()
                    ->issuedAt(new DateTimeImmutable('-100 second'))
                    ->canOnlyBeUsedAfter(new DateTimeImmutable('-100 second'))
                    ->expiresAt(new DateTimeImmutable('+900 second'))
                    ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
                    ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
                    ->toString(),
            ]);

        $this->ensureSameResponse($middleware, $validToken);
    }

    public function testAllowCustomRequestAttributeName(): void
    {
        $customAttributeName = 'my_custom_session_attribute_name';

        $middleware = new SessionMiddleware(
            $this->config
                ->withSessionAttribute($customAttributeName),
        );

        $middleware->process(
            new ServerRequest(),
            $this->fakeDelegate(static function (ServerRequestInterface $request) use ($customAttributeName) {
                self::assertInstanceOf(SessionInterface::class, $request->getAttribute($customAttributeName));
                self::assertNull($request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE));

                return new Response();
            }),
        );
    }

    public function testDefaultConfigurationShouldNotUseClientFingerprinting(): void
    {
        $response = $this->middleware->process(new ServerRequest(), $this->writingMiddleware());
        $token    = $this->getCookie($response)->getValue();

        self::assertIsString($token);
        self::assertTrue($token !== '');
        $parsedToken = (new Parser(new JoseEncoder()))->parse($token);
        self::assertInstanceOf(Plain::class, $parsedToken);
        self::assertFalse($parsedToken->claims()->has(SameOriginRequest::CLAIM));
    }

    public function testWithNonEmptyClientFingerprintConfigurationItShouldAddAndValidateFingerprint(): void
    {
        $serverParamKey   = 'foo';
        $serverParamValue = 'bar';

        $source = new class ($serverParamKey) implements Source {
            /** @param non-empty-string $serverParam */
            public function __construct(private readonly string $serverParam)
            {
            }

            public function extractFrom(ServerRequestInterface $request): string
            {
                $value = $request->getServerParams()[$this->serverParam];
                Assert::assertIsString($value);
                Assert::assertNotEmpty($value);

                return $value;
            }
        };

        $middleware = new SessionMiddleware(
            $this->config->withClientFingerprintConfiguration(FingerprintConfig::forSources($source)),
        );

        $request      = new ServerRequest([$serverParamKey => $serverParamValue]);
        $sessionValue = uniqid('fp_');
        $response     = $middleware->process($request, $this->writingMiddleware($sessionValue));
        $token        = $this->getCookie($response)->getValue();

        self::assertIsString($token);
        self::assertTrue($token !== '');
        $parsedToken = (new Parser(new JoseEncoder()))->parse($token);
        self::assertInstanceOf(Plain::class, $parsedToken);
        self::assertTrue($parsedToken->claims()->has(SameOriginRequest::CLAIM));

        $validNewRequest = $request->withCookieParams([$this->config->getCookie()->getName() => $token]);

        $middleware->process(
            $validNewRequest,
            $this->fakeDelegate(
                static function (ServerRequestInterface $request) use ($sessionValue) {
                    $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
                    assert($session instanceof SessionInterface);

                    self::assertSame($sessionValue, $session->get('foo'));

                    return new Response();
                },
            ),
        );

        $invalidNewRequest = (new ServerRequest([
            $serverParamKey => $serverParamValue . ' changed',
        ]))->withCookieParams([$this->config->getCookie()->getName() => $token]);

        $middleware->process(
            $invalidNewRequest,
            $this->emptyValidationMiddleware(),
        );
    }

    private function ensureSameResponse(
        SessionMiddleware $middleware,
        ServerRequestInterface $request,
        RequestHandlerInterface|null $next = null,
    ): ResponseInterface {
        $initialResponse = new Response();

        $handleRequest = $this->createMock(RequestHandlerInterface::class);

        if ($next === null) {
            $handleRequest
                ->expects(self::once())
                ->method('handle')
                ->willReturn($initialResponse);
        } else {
            // capturing `$initialResponse` from the `$next` handler
            $handleRequest
                ->expects(self::once())
                ->method('handle')
                ->willReturnCallback(static function (ServerRequestInterface $serverRequest) use ($next, & $initialResponse) {
                    $response = $next->handle($serverRequest);

                    $initialResponse = $response;

                    return $response;
                });
        }

        $response = $middleware->process($request, $handleRequest);

        self::assertSame($initialResponse, $response);

        return $response;
    }

    private function ensureClearsSessionCookie(
        SessionMiddleware $middleware,
        ServerRequestInterface $request,
        RequestHandlerInterface $next,
    ): ResponseInterface {
        $response = $middleware->process($request, $next);

        $cookie = $this->getCookie($response);

        self::assertLessThan((new DateTime('-29 day'))->getTimestamp(), $cookie->getExpires());
        self::assertEmpty($cookie->getValue());

        return $response;
    }

    private function createToken(Configuration $config, DateTimeImmutable $issuedAt, DateTimeImmutable $expiration): string
    {
        $jwtConfiguration = $config->getJwtConfiguration();

        return $jwtConfiguration->builder()
            ->issuedAt($issuedAt)
            ->canOnlyBeUsedAfter($issuedAt)
            ->expiresAt($expiration)
            ->withClaim(SessionMiddleware::SESSION_CLAIM, DefaultSessionData::fromTokenData(['foo' => 'bar']))
            ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
            ->toString();
    }

    private function createTokenWithCustomClaim(
        Configuration $config,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiration,
        mixed $claim,
    ): string {
        $jwtConfiguration = $config->getJwtConfiguration();

        return $jwtConfiguration->builder()
            ->issuedAt($issuedAt)
            ->canOnlyBeUsedAfter($issuedAt)
            ->expiresAt($expiration)
            ->withClaim(SessionMiddleware::SESSION_CLAIM, $claim)
            ->getToken($jwtConfiguration->signer(), $jwtConfiguration->signingKey())
            ->toString();
    }

    private function emptyValidationMiddleware(): RequestHandlerInterface
    {
        return $this->fakeDelegate(
            static function (ServerRequestInterface $request) {
                $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);

                self::assertInstanceOf(SessionInterface::class, $session);
                self::assertTrue($session->isEmpty());

                return new Response();
            },
        );
    }

    private function writingMiddleware(string $value = 'bar'): RequestHandlerInterface
    {
        return $this->fakeDelegate(
            static function (ServerRequestInterface $request) use ($value) {
                $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
                assert($session instanceof SessionInterface);
                $session->set('foo', $value);

                return new Response();
            },
        );
    }

    private function fakeDelegate(callable $callback): RequestHandlerInterface
    {
        $middleware = $this->createMock(RequestHandlerInterface::class);

        $middleware
            ->expects(self::once())
           ->method('handle')
           ->willReturnCallback($callback)
           ->with(self::isInstanceOf(RequestInterface::class));

        return $middleware;
    }

    private function requestWithResponseCookies(ResponseInterface $response): ServerRequest
    {
        return (new ServerRequest())->withCookieParams([
            $this->config->getCookie()->getName() => $this->getCookie($response)->getValue(),
        ]);
    }

    private function getCookie(ResponseInterface $response, string|null $name = null): SetCookie
    {
        $name ??= $this->config->getCookie()->getName();

        return FigResponseCookies::get($response, $name);
    }

    private static function makeRandomSymmetricKey(): Signer\Key\InMemory
    {
        return Signer\Key\InMemory::plainText('test-key_' . base64_encode(random_bytes(128)));
    }
}
