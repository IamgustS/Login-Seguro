<?php
declare(strict_types=1);

require __DIR__ . '/../app/security.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$secret = encodeBase32('12345678901234567890');
check(
    $secret === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    'Base32 encoding does not match the RFC 4648 vector.'
);
check(
    decodeBase32($secret) === '12345678901234567890',
    'Base32 decoding does not restore the original secret.'
);

$vectors = [
    59 => '287082',
    1111111109 => '081804',
    1111111111 => '050471',
    1234567890 => '005924',
    2000000000 => '279037',
];
foreach ($vectors as $timestamp => $expected) {
    check(
        getTotpCode($secret, intdiv($timestamp, 30)) === $expected,
        'TOTP code does not match the RFC 6238 vector at ' . $timestamp . '.'
    );
}

$currentCounter = intdiv(time(), 30);
$currentCode = getTotpCode($secret, $currentCounter);
check(
    verifyTotpCode($secret, $currentCode, $currentCounter - 1) === $currentCounter,
    'The current TOTP code should be accepted once.'
);
check(
    verifyTotpCode($secret, $currentCode, $currentCounter) === null,
    'A previously used TOTP counter should be rejected.'
);

$key = random_bytes(32);
$encrypted = encryptTotpSecret($secret, $key);
check(
    decryptTotpSecret($encrypted, $key) === $secret,
    'The encrypted TOTP secret did not decrypt correctly.'
);
$payload = base64_decode($encrypted, true);
$payload[28] = chr(ord($payload[28]) ^ 1);
$tamperedWasRejected = false;
try {
    decryptTotpSecret(base64_encode($payload), $key);
} catch (RuntimeException) {
    $tamperedWasRejected = true;
}
check($tamperedWasRejected, 'Tampered TOTP ciphertext was not rejected.');

$codes = createRecoveryCodes();
check(count($codes) === 8 && count(array_unique($codes)) === 8, 'Recovery codes must be unique.');
foreach ($codes as $code) {
    check(
        strlen($code) === 32 && normalizeRecoveryCode($code) === $code,
        'A generated recovery code has an invalid format.'
    );
}
check(
    normalizeRecoveryCode(substr($codes[0], 0, 16) . '-' . substr($codes[0], 16)) === $codes[0],
    'Recovery code formatting should tolerate a separator.'
);

echo "Security tests passed.\n";
