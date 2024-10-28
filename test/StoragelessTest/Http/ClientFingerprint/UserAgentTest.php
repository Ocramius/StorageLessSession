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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use PSR7Sessions\Storageless\Http\ClientFingerprint\SourceMissing;
use PSR7Sessions\Storageless\Http\ClientFingerprint\UserAgent;

#[CoversClass(UserAgent::class)]
#[CoversClass(SourceMissing::class)]
final class UserAgentTest extends TestCase
{
    private const HEADER_NAME = 'User-Agent';
    private UserAgent $source;

    protected function setUp(): void
    {
        $this->source = new UserAgent();
    }

    public function testReturnTheClientIp(): void
    {
        $ip      = 'Firefox';
        $request = new ServerRequest(headers: [self::HEADER_NAME => $ip]);

        self::assertSame($ip, $this->source->extractFrom($request));
    }

    public function testRequireParamToExist(): void
    {
        $this->expectException(SourceMissing::class);

        $this->source->extractFrom(new ServerRequest());
    }

    public function testRequireParamToBeString(): void
    {
        $request = new ServerRequest(headers: [self::HEADER_NAME => '']);

        $this->expectException(SourceMissing::class);

        $this->source->extractFrom($request);
    }

    public function testRequireParamToBeNonEmptyString(): void
    {
        $request = new ServerRequest(headers: [self::HEADER_NAME => '']);

        $this->expectException(SourceMissing::class);

        $this->source->extractFrom($request);
    }
}
