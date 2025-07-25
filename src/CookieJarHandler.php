<?php

namespace Biboletin\Cookie;

use Biboletin\Crypto\Crypto;
use Exception;
use Psr\Http\Message\ServerRequestInterface;

class CookieJarHandler
{
    protected array $cookies = [];

    protected bool $encrypt = false;
    protected Crypto $crypto;

    public function __construct(Crypto $crypto)
    {
        $this->crypto = $crypto;
    }

    public function add(CookieHandler $cookie): void
    {
        if ($this->encrypt) {
            $cookie->encrypt();
        }

        $this->cookies[$cookie->getName()] = $cookie;
    }

    public function get(string $name): ?CookieHandler
    {
        $cookie = $this->cookies[$name] ?? null;

        if ($cookie && $cookie->isExpired()) {
            $this->remove($name);

            return null;
        }

        if ($cookie && $this->encrypt) {
            $cookie->decrypt();
        }

        return $cookie;
    }

    public function all(): array
    {
        $validCookies = [];

        foreach ($this->cookies as $name => $cookie) {
            if (!$cookie->isExpired()) {
                if ($this->encrypt) {
                    $cookie->decrypt();
                }
                $validCookies[$name] = $cookie;
            } else {
                $this->remove($name);
            }
        }

        return $validCookies;
    }

    public function has(string $name): bool
    {
        return isset($this->cookies[$name]) && !$this->cookies[$name]->isExpired();
    }

    public function remove(string $name): void
    {
        unset($this->cookies[$name]);
    }

    public function clear(): void
    {
        $this->cookies = [];
    }

    public function setEncrypt(bool $encrypt): void
    {
        $this->encrypt = $encrypt;
    }

    public function isEncrypt(): bool
    {
        return $this->encrypt;
    }

    public function toHeader(): string
    {
        $parts = [];
        foreach ($this->all() as $cookie) {
            if (!$cookie->isExpired()) {
                $parts[] = $cookie->toHeader();
            }
        }

        return 'Cookie: ' . implode('; ', $parts);
    }

    public function toCurlHeader(): string
    {
        $parts = [];
        foreach ($this->all() as $cookie) {
            if (!$cookie->isExpired()) {
                $parts[] = rawurlencode($cookie->getName()) . '=' . rawurlencode($cookie->getValue());
            }
        }

        return implode('; ', $parts);
    }

    public function parseSetCookieHeader(array $setCookieHeaders, bool $decrypt = false): void
    {
        foreach ($setCookieHeaders as $header) {
            $parts = explode(';', $header);
            $nameValue = explode('=', array_shift($parts), 2);
            $name = trim($nameValue[0]);
            $value = isset($nameValue[1]) ? trim($nameValue[1]) : '';

            if ($decrypt) {
                try {
                    $value = $this->crypto->decrypt($value) ?? '';
                } catch (Exception $e) {
                    // Handle decryption failure, possibly log it
                    continue;
                }
            }

            $cookie = new CookieHandler();
            $cookie->setName($name)
                ->setValue($value);

            foreach ($parts as $part) {
                [$partName, $partValue] = array_map('trim', explode('=', $part, 2));

                switch (strtolower($partName)) {
                    case 'expires':
                        $cookie->setExpire(strtotime($partValue));
                        break;
                    case 'path':
                        $cookie->setPath($partValue);
                        break;
                    case 'domain':
                        $cookie->setDomain($partValue);
                        break;
                    case 'secure':
                        $cookie->setSecure(true);
                        break;
                    case 'httponly':
                        $cookie->setHttpOnly(true);
                        break;
                    case 'samesite':
                        $cookie->setSameSite($partValue);
                        break;
                    case 'raw':
                        $cookie->setRaw(true);
                        break;
                    case 'force':
                        $cookie->setForce(true);
                        break;
                    case 'secureonly':
                        $cookie->setSecureOnly(true);
                        break;
                }
            }
            $this->add($cookie);
        }
    }

    public function saveToCurlFile(string $cookieFilePath): bool
    {
        $lines = [
            "# Netscape HTTP Cookie File",
            "# This file was generated by CookieJarHandler",
            "# https://curl.se/docs/http-cookies.html",
            ""
        ];

        foreach ($this->all() as $cookie) {
            $domain = $cookie->getDomain() ?: 'localhost';
            $includeSubdomains = str_starts_with($domain, '.') ? 'true' : 'false';
            $path = $cookie->getPath() ?: '/';
            $secure = $cookie->getSecure() ? 'true' : 'false';
            $expires = $cookie->getExpire() ?? 2145916800; // default: 2038
            $name = $cookie->getName();
            $value = $cookie->getValue();

            $lines[] = implode("\t", [
                $domain,
                $includeSubdomains,
                $path,
                $secure,
                $expires,
                $name,
                $value
            ]);
        }

        return file_put_contents($cookieFilePath, implode(PHP_EOL, $lines)) !== false;
    }

    public function saveToFile(string $path): bool
    {
        $data = array_map(fn($cookie) => $cookie->toArray(), $this->all());

        return file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) !== false;
    }

    public function loadFromFile(string $path): bool
    {
        if (!file_exists($path)) {
            return false;
        }

        $content = file_get_contents($path) ?: '';
        $data = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return false;
        }

        foreach ($data as $cookieData) {
            $cookie = new CookieHandler();
            $cookie->fromArray($cookieData);
            $this->add($cookie);
        }

        return true;
    }

    public function toArray(): array
    {
        return array_map(fn($cookie) => $cookie->toArray(), $this->all());
    }

    public function loadFromArray(array $data): void
    {
        foreach ($data as $cookieData) {
            $cookie = new CookieHandler();
            $cookie->fromArray($cookieData);
            $this->add($cookie);
        }
    }

    public function send(): void
    {
        foreach ($this->all() as $cookie) {
            // If encryption is enabled and the value is not encrypted
            if ($this->encrypt && !$cookie->isEncrypted()) {
                $cookie->encrypt();
            }

            setcookie(
                $cookie->getName(),
                $cookie->getValue(),
                [
                    'expires' => $cookie->getExpire(),
                    'path' => $cookie->getPath(),
                    'domain' => $cookie->getDomain(),
                    'secure' => $cookie->isSecure(),
                    'httponly' => $cookie->isHttpOnly(),
                    'samesite' => $cookie->getSameSite() ?? 'Lax',
                ]
            );
        }
    }

    public function parseFromGlobals(bool $decrypt = false): void
    {
        foreach ($_COOKIE as $name => $value) {
            if ($decrypt) {
                try {
                    $value = $this->crypto->decrypt($value) ?? '';
                } catch (Exception $e) {
                    continue; // skip if decryption fails
                }
            }

            $cookie = new CookieHandler();
            $cookie->setName($name)->setValue($value);

            $this->add($cookie);
        }
    }

    public function parseFromRequest(ServerRequestInterface $request, bool $decrypt = false): void
    {
        foreach ($request->getCookieParams() as $name => $value) {
            if ($decrypt) {
                try {
                    $value = $this->crypto->decrypt($value) ?? '';
                } catch (Exception $e) {
                    continue;
                }
            }

            $cookie = new CookieHandler();
            $cookie->setName($name)->setValue($value);

            $this->add($cookie);
        }
    }

    public function getSetCookieHeaders(): array
    {
        $headers = [];
        foreach ($this->all() as $cookie) {
            $headers[] = $cookie->toHeader();
        }
        return $headers;
    }

}
