<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

use function base64_encode;
use function hash;
use function json_encode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * @internal
 *
 * @psalm-immutable
 */
final readonly class SameOriginRequest implements Constraint
{
    public const CLAIM = 'fp';

    /** @var list<Source> */
    private array $sources;
    /** @var non-empty-string */
    private string $currentRequestFingerprint;

    public function __construct(
        private Configuration $configuration,
        ServerRequestInterface $serverRequest,
    ) {
        $this->sources = $this->configuration->sources();
        if ($this->sources === []) {
            return;
        }

        $this->currentRequestFingerprint = self::getCurrentFingerprint($this->sources, $serverRequest);
    }

    public function assert(Token $token): void
    {
        if ($this->sources === []) {
            return;
        }

        if (! $token instanceof UnencryptedToken) {
            throw new RuntimeException(sprintf(
                'It was expected an %s, %s given',
                UnencryptedToken::class,
                $token::class,
            ));
        }

        if (! $token->claims()->has(self::CLAIM)) {
            throw ConstraintViolation::error('"Client Fingerprint" claim missing', $this);
        }

        if ($token->claims()->get(self::CLAIM) !== $this->currentRequestFingerprint) {
            throw ConstraintViolation::error('"Client Fingerprint" does not match', $this);
        }
    }

    public function configure(Builder $builder): Builder
    {
        if ($this->sources === []) {
            return $builder;
        }

        return $builder->withClaim(self::CLAIM, $this->currentRequestFingerprint);
    }

    /**
     * @param non-empty-list<Source> $sources
     *
     * @return non-empty-string
     */
    private static function getCurrentFingerprint(array $sources, ServerRequestInterface $serverRequest): string
    {
        $fingerprintSource = [];
        foreach ($sources as $source) {
            $fingerprintSource[] = $source->extractFrom($serverRequest);
        }

        return base64_encode(hash('sha256', json_encode($fingerprintSource, JSON_THROW_ON_ERROR), true));
    }
}
