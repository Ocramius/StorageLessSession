# PSR-7 Storage-less HTTP Sessions

[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fpsr7-sessions%2Fstorageless%2F9.2.x)](https://dashboard.stryker-mutator.io/reports/github.com/psr7-sessions/storageless/9.2.x)
[![Type Coverage](https://shepherd.dev/github/psr7-sessions/storageless/coverage.svg)](https://shepherd.dev/github/psr7-sessions/storageless)
[![Packagist](https://img.shields.io/packagist/v/psr7-sessions/storageless.svg)](https://packagist.org/packages/psr7-sessions/storageless)
[![Packagist](https://img.shields.io/packagist/vpre/psr7-sessions/storageless.svg)](https://packagist.org/packages/psr7-sessions/storageless)

**PSR7Session** is a [PSR-7](https://www.php-fig.org/psr/psr-7/) and
[PSR-15](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-15-request-handlers.md)
compatible [middleware](https://mwop.net/blog/2015-01-08-on-http-middleware-and-psr-7.html) that enables
session without I/O usage in PSR-7 based applications.

Proudly brought to you by [ocramius](https://github.com/Ocramius), [malukenho](https://github.com/malukenho) and [lcobucci](https://github.com/lcobucci).

## Installation

```sh
composer require psr7-sessions/storageless
```

## Usage

You can use the `PSR7Sessions\Storageless\Http\SessionMiddleware` in any
[PSR-15](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-15-request-handlers.md)
compatible middleware.

In a [`mezzio/mezzio`](https://github.com/mezzio/mezzio)
application, this would look like following:

```php
use Lcobucci\JWT\Configuration as JwtConfig;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use PSR7Sessions\Storageless\Http\SessionMiddleware;
use PSR7Sessions\Storageless\Http\Configuration as StoragelessConfig;

$app = new \Mezzio\Application(/* ... */);

$app->pipe(new SessionMiddleware(
    new StoragelessConfig(
        JwtConfig::forSymmetricSigner(
            new Signer\Hmac\Sha256(),
            InMemory::base64Encoded('OpcMuKmoxkhzW0Y1iESpjWwL/D3UBdDauJOe742BJ5Q='), // replace this with a key of your own (see below)
        )
    )
));
```

After this, you can access the session data inside any middleware that
has access to the `Psr\Http\Message\ServerRequestInterface` attributes:

```php
$app->get('/get', function (ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface {
    /** @var \PSR7Sessions\Storageless\Session\SessionInterface $session */
    $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
    $session->set('counter', $session->get('counter', 0) + 1);

    $response
        ->getBody()
        ->write('Counter Value: ' . $session->get('counter'));

    return $response;
});
```

You can do this also in asynchronous contexts and long-running processes,
since no super-globals nor I/O are involved.

It is recommended that you use a key with lots of entropy, preferably
generated using a cryptographically secure pseudo-random number generator
(CSPRNG). You can use the [CryptoKey tool](https://github.com/AndrewCarterUK/CryptoKey)
to do this for you.

Note that you can also use asymmetric keys; please refer to
[`lcobucci/jwt`](https://packagist.org/packages/lcobucci/jwt) documentation:

1. The `Configuration` object: https://lcobucci-jwt.readthedocs.io/en/stable/configuration/
2. Supported algorithms: https://lcobucci-jwt.readthedocs.io/en/stable/supported-algorithms/

### Session Hijacking mitigation

To mitigate the risks associated to cookie stealing and thus
[session hijacking](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#binding-the-session-id-to-other-user-properties),
you can bind the user session to its IP (`$_SERVER['REMOTE_ADDR']`) and
User-Agent (`$_SERVER['HTTP_USER_AGENT']`) by enabling client fingerprinting:

```php
use PSR7Sessions\Storageless\Http\SessionMiddleware;
use PSR7Sessions\Storageless\Http\Configuration as StoragelessConfig;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration as FingerprintConfig;

$app = new \Mezzio\Application(/* ... */);

$app->pipe(new SessionMiddleware(
    (new StoragelessConfig(/* ... */))
        ->withClientFingerprintConfiguration(
            FingerprintConfig::forIpAndUserAgent()
        )
));
```

If your PHP service is behind a reverse proxy of yours, [you may need to retrieve the client IP from a different source of truth](https://adam-p.ca/blog/2022/03/x-forwarded-for/).
In such cases you can extract the information you need by writing a custom
`\PSR7Sessions\Storageless\Http\ClientFingerprint\Source` implementation:

```php
use Psr\Http\Message\ServerRequestInterface;
use PSR7Sessions\Storageless\Http\SessionMiddleware;
use PSR7Sessions\Storageless\Http\Configuration as StoragelessConfig;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Configuration as FingerprintConfig;
use PSR7Sessions\Storageless\Http\ClientFingerprint\Source;

$app = new \Mezzio\Application(/* ... */);

$app->pipe(new SessionMiddleware(
    (new StoragelessConfig(/* ... */))
        ->withClientFingerprintConfiguration(
            FingerprintConfig::forSources(new class implements Source{
                 public function extractFrom(ServerRequestInterface $request): string
                 {
                     return $request->getHeaderLine('X-Real-IP');
                 }
            })
        )
));
```

### Examples

Simply browse to the `examples` directory in your console, then run

```sh
php -S localhost:9999 index.php
```

Then try accessing `http://localhost:9999`: you should see a counter
that increases at every page refresh

## WHY?

In most PHP+HTTP related projects, `ext/session` serves its purpose and
allows us to store server-side information by associating a certain
identifier to a visiting user-agent.

## What is the problem with `ext/session`?

This is all fair and nice, except for:

* relying on the `$_SESSION` superglobal
* relying on the shutdown handlers in order to "commit" sessions to the
  storage
* having a huge limitation of number of active users (due to storage)
* having a lot of I/O due to storage
* having serialized data cross different processes (PHP serializes and
  de-serializes `$_SESSION` for you, and there are security implications)
* having to use a centralized storage for setups that scale horizontally
* having to use sticky sessions (with a "smart" load-balancer) when the
  storage is not centralized
* not designed to be used for multiple dispatch cycles

## What does this project do?

This project tries to implement storage-less sessions and to mitigate the
issues listed above.

## Assumptions

* your sessions are fairly small and contain only few identifiers and
  some CSRF tokens. Small means `< 400` bytes
* data in your session is `JsonSerializable` or equivalent
* data in your session is **freely readable by the client**

## How does it work?

Session data is directly stored inside a session cookie as a JWT token.

This approach is not new, and is commonly used with `Bearer` tokens in
HTTP/REST/OAuth APIs.

In order to guarantee that the session data is not modified, that the
client can trust the information and that the expiration date is
mutually agreed between server and client, a [JWT token](https://tools.ietf.org/html/rfc7519)
is used to transmit the information.

The JWT token is always signed to ensure that the user-agent is never
able to manipulate the session.
Both symmetric and asymmetric keys are supported for signing/verifying
tokens.

## Advantages

* no storage required
* no sticky sessions required (any server having a copy of the private or
  public keys can generate sessions or consume them)
* can transmit cleartext information to the client, allowing it to share
  some information with the server (a standard example is about sharing the
  "username" or "user-id" in a given session)
* can transmit encrypted information to the client, allowing server-only
  consumption of the information
* not affected by PHP serialization RCE attacks
* not limited to PHP process scope: can have many sessions per process
* no reliance on global state
* when in a multi-server setup, you may allow read-only access to servers
  that only have access to public keys, while writes are limited to
  servers that have access to private keys
* can be used over multiple dispatch cycles

## Configuration options

Please refer to the [configuration documentation](docs/configuration.md).

## Known limitations

Please refer to the [limitations documentation](docs/limitations.md).

## Contributing

Please refer to the [contributing notes](CONTRIBUTING.md).

## License

This project is made public under the [MIT LICENSE](LICENSE).
