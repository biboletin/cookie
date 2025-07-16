<?php
/**
 * Example script demonstrating the usage of the Cookie class.
 * 
 * This script shows how to create, configure, use, and destroy a session.
 */


// Include Composer autoloader
include __DIR__ . '/vendor/autoload.php';

use Biboletin\Cookie\CookieHandler;
use Biboletin\Cookie\CookieJarHandler;
use Biboletin\Crypto\Crypto;

// Create a new Cookie instance
$cookie = new CookieHandler();
// Set cookie properties
$cookie
    ->encrypt(true)
    ->setExpire(time() + 3600) // 1 hour from now
    ->setPath('/')
    ->setDomain('localhost')
    ->setSecure(true)
    ->setHttpOnly(true)
    ->setSameSite('Lax')
    ->setRaw(false)
    ->setForce(false)
    ->setPartitioned(true)
    ->setSecureOnly(false);

// dd($cookie->getValue());
// Send the cookie to the browser
$cookie->set('is_logged_in', true);
$cookie->set('user_id', 12345);
$cookie->set('session_token', 'abc123xyz');
$cookie->set('user_theme', 'dark');

$cookie->send();

$cookieJar = new CookieJarHandler(new Crypto('cookie'));
// $cookieJar->setEncrypt(true);
$cookieJar->add($cookie);
$cookieJar->saveToFile(__DIR__ . '/cookie.txt');
$cookieJar->saveToCurlFile(__DIR__ . '/cookie-jar.txt');
