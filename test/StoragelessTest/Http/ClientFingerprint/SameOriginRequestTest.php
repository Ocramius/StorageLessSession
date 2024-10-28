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

namespace PSR7SessionsTest\Storageless\Http\ClientFingerprint;

use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Blake2b;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration;
use PSR7Sessions\Storageless\Http\ClientFingerprint\SameOriginRequest;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Source;
use RuntimeException;

use function strlen;

#[CoversClass(SameOriginRequest::class)]
final class SameOriginRequestTest extends TestCase
{
    private const SOURCE_DATA = 'ID';

    private Source $source;
    private Configuration $configuration;
    private ServerRequest $request;
    private SameOriginRequest $constraint;
    private Token\Builder $builder;
    private Signer $signer;
    private Signer\Key $key;

    protected function setUp(): void
    {
        $this->source        = new class (self::SOURCE_DATA) implements Source {
            /** @param non-empty-string $data */
            public function __construct(
                private readonly string $data,
            ) {
            }

            public function extractFrom(ServerRequestInterface $request): string
            {
                return $this->data;
            }
        };
        $this->configuration = Configuration::forSources($this->source);
        $this->request       = new ServerRequest();
        $this->constraint    = new SameOriginRequest($this->configuration, $this->request);
        $this->builder       = new Token\Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());

        $this->signer = new Blake2b();
        $this->key    = InMemory::base64Encoded('K9c4Wq2rO9Upc3/diteodLudLkFjczY6ny7ebrTm/TA=');
    }

    public function testWhenDisabledTheTokenIsAlwaysValid(): void
    {
        $constraint = $this->getDisabledConstraint();

        $constraint->assert($this->createMock(Token::class));
    }

    public function testShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('It was expected an Lcobucci\\JWT\\UnencryptedToken');

        $this->constraint->assert($this->createMock(Token::class));
    }

    public function testShouldRaiseExceptionWhenClaimIsAbsent(): void
    {
        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('"Client Fingerprint" claim missing');

        $this->constraint->assert($this->buildToken());
    }

    public function testShouldRaiseExceptionWhenFingerprintDoesNotMatch(): void
    {
        $token = $this->buildToken([SameOriginRequest::CLAIM => self::SOURCE_DATA . ' changed']);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('"Client Fingerprint" does not match');

        $this->constraint->assert($token);
    }

    public function testWhenDisabledItDoesntAddAnyAdditionalClaim(): void
    {
        $constraint = $this->getDisabledConstraint();
        $newBuilder = $constraint->configure($this->builder);

        self::assertSame(
            $this->builder->getToken($this->signer, $this->key)->claims()->all(),
            $newBuilder->getToken($this->signer, $this->key)->claims()->all(),
        );
    }

    public function testShouldAddFingerprintClaim(): void
    {
        $newBuilder = $this->constraint->configure($this->builder);
        $claims     = $newBuilder->getToken($this->signer, $this->key)->claims();

        self::assertTrue($claims->has(SameOriginRequest::CLAIM));

        $fingerprintClaim = $claims->get(SameOriginRequest::CLAIM);
        self::assertIsString($fingerprintClaim);
        self::assertNotEmpty($fingerprintClaim);
        self::assertSame(44, strlen($fingerprintClaim));
    }

    public function testFingerprintShouldDependOnAllConfiguredSources(): void
    {
        $sourceOne          = new class implements Source {
            public function extractFrom(ServerRequestInterface $request): string
            {
                return 'one';
            }
        };
        $sourceTwo          = new class implements Source {
            public function extractFrom(ServerRequestInterface $request): string
            {
                return 'two';
            }
        };
        $sourceOneTwoHacked = new class implements Source {
            public function extractFrom(ServerRequestInterface $request): string
            {
                return 'onetwo';
            }
        };

        $constraintOne          = new SameOriginRequest(Configuration::forSources($sourceOne), $this->request);
        $constraintOneTwo       = new SameOriginRequest(Configuration::forSources($sourceOne, $sourceTwo), $this->request);
        $constraintTwoOne       = new SameOriginRequest(Configuration::forSources($sourceTwo, $sourceOne), $this->request);
        $constraintOneTwoHacked = new SameOriginRequest(Configuration::forSources($sourceOneTwoHacked), $this->request);

        $claimsOne          = $constraintOne->configure($this->builder)->getToken($this->signer, $this->key)->claims();
        $claimsOneTwo       = $constraintOneTwo->configure($this->builder)->getToken($this->signer, $this->key)->claims();
        $claimsTwoOne       = $constraintTwoOne->configure($this->builder)->getToken($this->signer, $this->key)->claims();
        $claimsOneTwoHacked = $constraintOneTwoHacked->configure($this->builder)->getToken($this->signer, $this->key)->claims();

        $fingerprintOne          = $claimsOne->get(SameOriginRequest::CLAIM);
        $fingerprintOneTwo       = $claimsOneTwo->get(SameOriginRequest::CLAIM);
        $fingerprintTwoOne       = $claimsTwoOne->get(SameOriginRequest::CLAIM);
        $fingerprintOneTwoHacked = $claimsOneTwoHacked->get(SameOriginRequest::CLAIM);

        self::assertIsString($fingerprintOne);
        self::assertNotEmpty($fingerprintOne);
        self::assertIsString($fingerprintOneTwo);
        self::assertNotEmpty($fingerprintOneTwo);
        self::assertIsString($fingerprintTwoOne);
        self::assertNotEmpty($fingerprintTwoOne);
        self::assertIsString($fingerprintOneTwoHacked);
        self::assertNotEmpty($fingerprintOneTwoHacked);

        self::assertNotSame($fingerprintOne, $fingerprintOneTwo);
        self::assertNotSame($fingerprintOne, $fingerprintTwoOne);
        self::assertNotSame($fingerprintOneTwo, $fingerprintTwoOne);
        self::assertNotSame($fingerprintOneTwo, $fingerprintOneTwoHacked);
    }

    public function testShouldHashFingerprintSources(): void
    {
        $newBuilder = $this->constraint->configure($this->builder);
        $claims     = $newBuilder->getToken($this->signer, $this->key)->claims();

        $fingerprint = $claims->get(SameOriginRequest::CLAIM);
        self::assertIsString($fingerprint);
        self::assertNotEmpty($fingerprint);
        self::assertStringNotContainsString(self::SOURCE_DATA, $fingerprint);
    }

    /** @param array<non-empty-string, mixed> $claims */
    private function buildToken(
        array $claims = [],
    ): Plain {
        return new Plain(
            new DataSet([], ''),
            new DataSet($claims, ''),
            new Signature('sig+hash', 'sig+encoded'),
        );
    }

    private function getDisabledConstraint(): SameOriginRequest
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(self::never())->method('getMethod');

        return new SameOriginRequest(
            Configuration::disabled(),
            $request,
        );
    }
}
