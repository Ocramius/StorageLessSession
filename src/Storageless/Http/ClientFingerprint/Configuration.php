<?php

declare(strict_types=1);

namespace PSR7Sessions\Storageless\Http\ClientFingerprint;

final readonly class Configuration
{
    /** @var list<Source> */
    private array $sources;

    /**
     * @param list<Source> ...$sources
     *
     * @no-named-arguments
     */
    private function __construct(
        Source ...$sources,
    ) {
        $this->sources = $sources;
    }

    public static function disabled(): self
    {
        return new self();
    }

    /**
     * @param list<Source> ...$sources
     *
     * @no-named-arguments
     */
    public static function forSources(Source ...$sources): self
    {
        return new self(...$sources);
    }

    public static function forIpAndUserAgent(): self
    {
        return new self(new RemoteAddr(), new UserAgent());
    }

    /** @return list<Source> */
    public function sources(): array
    {
        return $this->sources;
    }
}
