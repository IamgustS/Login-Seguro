<?php
declare(strict_types=1);

require __DIR__ . '/app/security.php';
startSecureSession();

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $location): never
{
    header('Location: ' . $location, true, 303);
    exit;
}

function getDatabase(): PDO
{
    $driver = getenv('AUTH_DB_DRIVER') ?: 'sqlite';

    if ($driver === 'sqlite') {
        $databasePath = getenv('AUTH_DB_PATH');
        if ($databasePath === false || $databasePath === '') {
            $localAppData = getenv('LOCALAPPDATA') ?: sys_get_temp_dir();
            $databaseDirectory = $localAppData . DIRECTORY_SEPARATOR . 'AsterLogin';
            if (!is_dir($databaseDirectory) && !mkdir($databaseDirectory, 0700, true) && !is_dir($databaseDirectory)) {
                throw new RuntimeException('Não foi possível preparar o armazenamento local.');
            }
            $databasePath = $databaseDirectory . DIRECTORY_SEPARATOR . 'users.sqlite';
        }

        $pdo = new PDO('sqlite:' . $databasePath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(254) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                totp_secret TEXT NULL,
                totp_pending_secret TEXT NULL,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                totp_last_counter INTEGER NOT NULL DEFAULT -1
            )'
        );
        $columns = $pdo->query('PRAGMA table_info(users)')->fetchAll(PDO::FETCH_COLUMN, 1);
        $migrations = [
            'totp_secret' => 'ALTER TABLE users ADD COLUMN totp_secret TEXT NULL',
            'totp_pending_secret' => 'ALTER TABLE users ADD COLUMN totp_pending_secret TEXT NULL',
            'totp_enabled' => 'ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0',
            'totp_last_counter' => 'ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT -1',
        ];
        foreach ($migrations as $column => $migration) {
            if (!in_array($column, $columns, true)) {
                $pdo->exec($migration);
            }
        }
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS login_attempts (
                bucket_key CHAR(64) PRIMARY KEY,
                failures INTEGER NOT NULL DEFAULT 0,
                window_started TEXT NOT NULL,
                locked_until TEXT NULL
            )'
        );
        $pdo->exec('CREATE INDEX IF NOT EXISTS login_attempts_locked_until ON login_attempts (locked_until)');
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash CHAR(64) NOT NULL,
                UNIQUE (user_id, code_hash)
            )'
        );

        return $pdo;
    }

    if ($driver !== 'mysql') {
        throw new RuntimeException('O driver de banco de dados configurado não é suportado.');
    }

    $host = getenv('AUTH_DB_HOST') ?: '127.0.0.1';
    $port = getenv('AUTH_DB_PORT') ?: '3306';
    $database = getenv('AUTH_DB_NAME') ?: 'login_app';
    $username = getenv('AUTH_DB_USER');
    $password = getenv('AUTH_DB_PASSWORD');

    if ($username === false || $username === '' || $password === false) {
        throw new RuntimeException('As variáveis de acesso ao banco não foram configuradas.');
    }

    $pdo = new PDO(
        "mysql:host={$host};port={$port};dbname={$database};charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
    $columns = $pdo->query('SHOW COLUMNS FROM users')->fetchAll(PDO::FETCH_COLUMN, 0);
    $migrations = [
        'totp_secret' => 'ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255) NULL',
        'totp_pending_secret' => 'ALTER TABLE users ADD COLUMN totp_pending_secret VARCHAR(255) NULL',
        'totp_enabled' => 'ALTER TABLE users ADD COLUMN totp_enabled TINYINT(1) NOT NULL DEFAULT 0',
        'totp_last_counter' => 'ALTER TABLE users ADD COLUMN totp_last_counter BIGINT NOT NULL DEFAULT -1',
    ];
    foreach ($migrations as $column => $migration) {
        if (!in_array($column, $columns, true)) {
            $pdo->exec($migration);
        }
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS recovery_codes (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            code_hash CHAR(64) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY recovery_codes_user_hash (user_id, code_hash),
            CONSTRAINT recovery_codes_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB'
    );

    return $pdo;
}

function getCsrfToken(): string
{
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function getRateLimitKeys(string $email, string $ip): array
{
    return [
        'account' => hash('sha256', "account\0{$email}\0{$ip}"),
        'ip' => hash('sha256', "ip\0{$ip}"),
    ];
}

function getLockRemaining(PDO $pdo, array $keys): int
{
    if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
        $statement = $pdo->prepare(
            "SELECT MAX(CAST((julianday(locked_until) - julianday('now')) * 86400 AS INTEGER)) AS remaining
             FROM login_attempts
             WHERE bucket_key IN (:account_key, :ip_key)
               AND locked_until > datetime('now')"
        );
        $statement->execute([
            'account_key' => $keys['account'],
            'ip_key' => $keys['ip'],
        ]);

        return max(0, (int) ($statement->fetch()['remaining'] ?? 0));
    }

    $statement = $pdo->prepare(
        'SELECT MAX(TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), locked_until)) AS remaining
         FROM login_attempts
         WHERE bucket_key IN (:account_key, :ip_key)
           AND locked_until > UTC_TIMESTAMP()'
    );
    $statement->execute([
        'account_key' => $keys['account'],
        'ip_key' => $keys['ip'],
    ]);

    return max(0, (int) ($statement->fetch()['remaining'] ?? 0));
}

function recordFailedAttempt(PDO $pdo, string $key, int $limit): void
{
    if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
        $cleanup = $pdo->prepare(
            "DELETE FROM login_attempts
             WHERE window_started <= datetime('now', '-30 minutes')
               AND (locked_until IS NULL OR locked_until <= datetime('now'))"
        );
        $cleanup->execute();

        $statement = $pdo->prepare(
            "INSERT INTO login_attempts (bucket_key, failures, window_started, locked_until)
             VALUES (:bucket_key, 1, datetime('now'), NULL)
             ON CONFLICT(bucket_key) DO UPDATE SET
               locked_until = CASE
                 WHEN login_attempts.window_started <= datetime('now', '-15 minutes') THEN NULL
                 WHEN login_attempts.failures >= :threshold THEN datetime('now', '+15 minutes')
                 ELSE login_attempts.locked_until
               END,
               failures = CASE
                 WHEN login_attempts.window_started <= datetime('now', '-15 minutes') THEN 1
                 ELSE login_attempts.failures + 1
               END,
               window_started = CASE
                 WHEN login_attempts.window_started <= datetime('now', '-15 minutes') THEN datetime('now')
                 ELSE login_attempts.window_started
               END"
        );
        $statement->execute([
            'bucket_key' => $key,
            'threshold' => $limit - 1,
        ]);

        return;
    }

    $cleanup = $pdo->prepare(
        'DELETE FROM login_attempts
         WHERE window_started <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 MINUTE)
           AND (locked_until IS NULL OR locked_until <= UTC_TIMESTAMP())'
    );
    $cleanup->execute();

    $threshold = max(0, $limit - 1);
    $statement = $pdo->prepare(
        "INSERT INTO login_attempts (bucket_key, failures, window_started, locked_until)
         VALUES (:bucket_key, 1, UTC_TIMESTAMP(), NULL)
         ON DUPLICATE KEY UPDATE
           locked_until = CASE
             WHEN window_started <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE) THEN NULL
             WHEN failures >= :threshold THEN DATE_ADD(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)
             ELSE locked_until
           END,
           failures = CASE
             WHEN window_started <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE) THEN 1
             ELSE failures + 1
           END,
           window_started = CASE
             WHEN window_started <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE) THEN UTC_TIMESTAMP()
             ELSE window_started
           END"
    );
    $statement->execute([
        'bucket_key' => $key,
        'threshold' => $threshold,
    ]);
}

function clearFailedAttempts(PDO $pdo, array $keys): void
{
    $statement = $pdo->prepare(
        'DELETE FROM login_attempts WHERE bucket_key IN (:account_key, :ip_key)'
    );
    $statement->execute([
        'account_key' => $keys['account'],
        'ip_key' => $keys['ip'],
    ]);
}

function getDatabaseDriver(PDO $pdo): string
{
    return (string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
}

function getDatabasePath(): string
{
    $path = getenv('AUTH_DB_PATH');
    if ($path !== false && $path !== '') {
        return $path;
    }

    $localAppData = getenv('LOCALAPPDATA') ?: sys_get_temp_dir();

    return $localAppData . DIRECTORY_SEPARATOR . 'AsterLogin' . DIRECTORY_SEPARATOR . 'users.sqlite';
}

function storeTotpCounter(PDO $pdo, int $userId, int $counter): bool
{
    $statement = $pdo->prepare(
        'UPDATE users
         SET totp_last_counter = :new_counter
         WHERE id = :id AND totp_last_counter < :previous_counter'
    );
    $statement->execute([
        'new_counter' => $counter,
        'id' => $userId,
        'previous_counter' => $counter,
    ]);

    return $statement->rowCount() === 1;
}

function verifyTotpOrRecoveryCode(PDO $pdo, array $user, string $input, string $driver, string $databasePath): bool
{
    $code = trim($input);
    $secret = decryptTotpSecret(
        (string) $user['totp_secret'],
        getTotpEncryptionKey($driver, $databasePath)
    );
    $counter = verifyTotpCode($secret, $code, (int) $user['totp_last_counter']);
    if ($counter !== null) {
        return storeTotpCounter($pdo, (int) $user['id'], $counter);
    }

    $recoveryCode = normalizeRecoveryCode($code);
    if ($recoveryCode === null) {
        return false;
    }

    $statement = $pdo->prepare(
        'DELETE FROM recovery_codes WHERE user_id = :user_id AND code_hash = :code_hash'
    );
    $statement->execute([
        'user_id' => $user['id'],
        'code_hash' => hash('sha256', $recoveryCode),
    ]);

    return $statement->rowCount() === 1;
}

function completeAuthentication(array $user): never
{
    session_regenerate_id(true);
    unset(
        $_SESSION['pending_2fa_user_id'],
        $_SESSION['pending_2fa_email'],
        $_SESSION['pending_2fa_expires']
    );
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'email' => (string) $user['email'],
    ];
    $_SESSION['_started_at'] = time();
    $_SESSION['_last_activity'] = time();
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['notice'] = 'Login realizado com sucesso.';
    redirect('./');
}

function processPost(PDO $pdo): array
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return ['mode' => 'login', 'error' => ''];
    }

    $action = (string) ($_POST['action'] ?? '');
    $mode = $action === 'register' ? 'register' : 'login';
    if (!hash_equals(getCsrfToken(), (string) ($_POST['csrf_token'] ?? ''))) {
        http_response_code(400);

        return ['mode' => $mode, 'error' => 'Sua sessão expirou. Atualize a página e tente novamente.'];
    }

    $authenticatedUser = $_SESSION['user'] ?? null;
    if ($action === 'logout') {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['_started_at'] = time();
        $_SESSION['_last_activity'] = time();
        $_SESSION['notice'] = 'Você saiu da sua conta com segurança.';
        redirect('./');
    }

    if ($action === 'cancel_2fa') {
        unset(
            $_SESSION['pending_2fa_user_id'],
            $_SESSION['pending_2fa_email'],
            $_SESSION['pending_2fa_expires']
        );
        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['notice'] = 'Verificação cancelada. Entre novamente para continuar.';
        redirect('./');
    }

    if ($action === 'verify_2fa') {
        $userId = (int) ($_SESSION['pending_2fa_user_id'] ?? 0);
        $email = (string) ($_SESSION['pending_2fa_email'] ?? '');
        $keys = getRateLimitKeys($email, (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        if (
            $userId < 1
            || (int) ($_SESSION['pending_2fa_expires'] ?? 0) < time()
        ) {
            unset(
                $_SESSION['pending_2fa_user_id'],
                $_SESSION['pending_2fa_email'],
                $_SESSION['pending_2fa_expires']
            );
            return ['mode' => 'login', 'error' => 'A verificação expirou. Entre novamente.'];
        }

        if (getLockRemaining($pdo, $keys) > 0) {
            return ['mode' => 'login', 'error' => 'Não foi possível verificar agora. Aguarde alguns minutos e tente novamente.'];
        }

        $statement = $pdo->prepare(
            'SELECT id, email, totp_secret, totp_enabled, totp_last_counter
             FROM users WHERE id = :id AND totp_enabled = 1 LIMIT 1'
        );
        $statement->execute(['id' => $userId]);
        $user = $statement->fetch();
        $valid = $user && verifyTotpOrRecoveryCode(
            $pdo,
            $user,
            (string) ($_POST['totp_code'] ?? ''),
            getDatabaseDriver($pdo),
            getDatabasePath()
        );

        if ($valid) {
            clearFailedAttempts($pdo, $keys);
            completeAuthentication($user);
        }

        recordFailedAttempt($pdo, $keys['account'], 5);
        recordFailedAttempt($pdo, $keys['ip'], 20);

        return ['mode' => 'login', 'error' => 'O código é inválido ou já foi utilizado. Tente novamente.'];
    }

    if ($action === 'start_totp') {
        if (!$authenticatedUser) {
            http_response_code(403);
            return ['mode' => 'login', 'error' => 'Entre na sua conta para configurar a verificação.'];
        }

        $secret = encodeBase32(random_bytes(20));
        $encryptedSecret = encryptTotpSecret(
            $secret,
            getTotpEncryptionKey(getDatabaseDriver($pdo), getDatabasePath())
        );
        $statement = $pdo->prepare(
            'UPDATE users SET totp_pending_secret = :secret
             WHERE id = :id AND totp_enabled = 0'
        );
        $statement->execute(['secret' => $encryptedSecret, 'id' => $authenticatedUser['id']]);
        if ($statement->rowCount() !== 1) {
            $_SESSION['notice'] = 'A verificação em duas etapas já está ativa.';
        }
        redirect('./');
    }

    if ($action === 'cancel_totp') {
        if ($authenticatedUser) {
            $statement = $pdo->prepare(
                'UPDATE users SET totp_pending_secret = NULL WHERE id = :id AND totp_enabled = 0'
            );
            $statement->execute(['id' => $authenticatedUser['id']]);
            $_SESSION['notice'] = 'Configuração do autenticador cancelada.';
        }
        redirect('./');
    }

    if ($action === 'confirm_totp') {
        $keys = getRateLimitKeys(
            (string) ($authenticatedUser['email'] ?? ''),
            (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
        );
        if (getLockRemaining($pdo, $keys) > 0) {
            return ['mode' => 'login', 'error' => 'Muitas tentativas. Aguarde alguns minutos e tente novamente.'];
        }
        $statement = $pdo->prepare(
            'SELECT totp_pending_secret FROM users WHERE id = :id AND totp_enabled = 0'
        );
        $statement->execute(['id' => $authenticatedUser['id'] ?? 0]);
        $pendingSecret = $statement->fetchColumn();
        if (!is_string($pendingSecret) || $pendingSecret === '') {
            return ['mode' => 'login', 'error' => 'Inicie novamente a configuração do autenticador.'];
        }

        $secret = decryptTotpSecret(
            $pendingSecret,
            getTotpEncryptionKey(getDatabaseDriver($pdo), getDatabasePath())
        );
        $counter = verifyTotpCode($secret, (string) ($_POST['totp_code'] ?? ''));
        if ($counter === null) {
            recordFailedAttempt($pdo, $keys['account'], 5);
            recordFailedAttempt($pdo, $keys['ip'], 20);
            return ['mode' => 'login', 'error' => 'Código inválido. Confira o aplicativo e tente novamente.'];
        }

        $codes = createRecoveryCodes();
        $pdo->beginTransaction();
        $statement = $pdo->prepare(
            'UPDATE users
             SET totp_secret = totp_pending_secret,
                 totp_pending_secret = NULL,
                 totp_enabled = 1,
                 totp_last_counter = :counter
             WHERE id = :id AND totp_enabled = 0'
        );
        $statement->execute(['counter' => $counter, 'id' => $authenticatedUser['id']]);
        if ($statement->rowCount() !== 1) {
            $pdo->rollBack();
            return ['mode' => 'login', 'error' => 'Não foi possível ativar o autenticador. Atualize a página e tente novamente.'];
        }

        $statement = $pdo->prepare(
            'INSERT INTO recovery_codes (user_id, code_hash) VALUES (:user_id, :code_hash)'
        );
        foreach ($codes as $code) {
            $statement->execute([
                'user_id' => $authenticatedUser['id'],
                'code_hash' => hash('sha256', $code),
            ]);
        }
        $pdo->commit();
        clearFailedAttempts($pdo, $keys);
        $_SESSION['recovery_codes_flash'] = $codes;
        $_SESSION['notice'] = 'Verificação em duas etapas ativada.';
        redirect('./');
    }

    if ($action === 'disable_totp') {
        if (!$authenticatedUser) {
            http_response_code(403);
            return ['mode' => 'login', 'error' => 'Entre na sua conta para alterar a segurança.'];
        }

        $statement = $pdo->prepare(
            'SELECT id, email, password_hash, totp_secret, totp_enabled, totp_last_counter
             FROM users WHERE id = :id AND totp_enabled = 1'
        );
        $statement->execute(['id' => $authenticatedUser['id']]);
        $user = $statement->fetch();
        $keys = getRateLimitKeys(
            (string) ($authenticatedUser['email'] ?? ''),
            (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown')
        );
        if (getLockRemaining($pdo, $keys) > 0) {
            return ['mode' => 'login', 'error' => 'Muitas tentativas. Aguarde alguns minutos e tente novamente.'];
        }
        $password = (string) ($_POST['password'] ?? '');
        if (
            !$user
            || strlen($password) > 1024
            || !password_verify($password, $user['password_hash'])
            || !verifyTotpOrRecoveryCode(
                $pdo,
                $user,
                (string) ($_POST['totp_code'] ?? ''),
                getDatabaseDriver($pdo),
                getDatabasePath()
            )
        ) {
            recordFailedAttempt($pdo, $keys['account'], 5);
            recordFailedAttempt($pdo, $keys['ip'], 20);
            return ['mode' => 'login', 'error' => 'Senha ou código de verificação inválido.'];
        }

        $pdo->beginTransaction();
        $statement = $pdo->prepare(
            'UPDATE users
             SET totp_secret = NULL, totp_pending_secret = NULL,
                 totp_enabled = 0, totp_last_counter = -1
             WHERE id = :id'
        );
        $statement->execute(['id' => $user['id']]);
        $statement = $pdo->prepare('DELETE FROM recovery_codes WHERE user_id = :user_id');
        $statement->execute(['user_id' => $user['id']]);
        $pdo->commit();
        clearFailedAttempts($pdo, $keys);
        $_SESSION['notice'] = 'Verificação em duas etapas desativada.';
        redirect('./');
    }

    if ($action === 'register') {
        $email = strtolower(trim((string) ($_POST['email'] ?? '')));
        $password = (string) ($_POST['password'] ?? '');
        $confirmation = (string) ($_POST['password_confirmation'] ?? '');
        $maximumPasswordLength = defined('PASSWORD_ARGON2ID') ? 1024 : 72;

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
            return ['mode' => 'register', 'error' => 'Informe um e-mail válido.'];
        }
        if (strlen($password) < 12 || strlen($password) > $maximumPasswordLength) {
            return ['mode' => 'register', 'error' => 'Use uma senha de pelo menos 12 caracteres e dentro do limite suportado.'];
        }
        if (!hash_equals($password, $confirmation)) {
            return ['mode' => 'register', 'error' => 'As senhas não coincidem.'];
        }

        $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        $statement = $pdo->prepare(
            'INSERT INTO users (email, password_hash) VALUES (:email, :password_hash)'
        );
        try {
            $statement->execute([
                'email' => $email,
                'password_hash' => password_hash($password, $algorithm),
            ]);
            $_SESSION['notice'] = 'Conta criada. Agora você já pode entrar.';
            redirect('./');
        } catch (PDOException $exception) {
            if ($exception->getCode() === '23000') {
                return ['mode' => 'register', 'error' => 'Não foi possível criar a conta com esses dados.'];
            }
            throw $exception;
        }
    }

    if ($action === 'login') {
        $email = strtolower(trim((string) ($_POST['email'] ?? '')));
        $password = (string) ($_POST['password'] ?? '');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $keys = getRateLimitKeys($email, $ip);

        if (getLockRemaining($pdo, $keys) > 0) {
            return ['mode' => 'login', 'error' => 'Não foi possível entrar agora. Aguarde alguns minutos e tente novamente.'];
        }

        $maximumPasswordLength = defined('PASSWORD_ARGON2ID') ? 1024 : 72;
        if (
            !filter_var($email, FILTER_VALIDATE_EMAIL)
            || strlen($email) > 254
            || strlen($password) > $maximumPasswordLength
        ) {
            recordFailedAttempt($pdo, $keys['account'], 5);
            recordFailedAttempt($pdo, $keys['ip'], 20);
            return ['mode' => 'login', 'error' => 'E-mail ou senha incorretos.'];
        }

        $statement = $pdo->prepare(
            'SELECT id, email, password_hash, totp_secret, totp_enabled
             FROM users WHERE email = :email LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();

        $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        static $dummyHash = null;
        if ($dummyHash === null) {
            $dummyHash = password_hash(bin2hex(random_bytes(32)), $algorithm);
        }
        $verified = password_verify($password, $user['password_hash'] ?? $dummyHash);
        if (!$user || !$verified) {
            recordFailedAttempt($pdo, $keys['account'], 5);
            recordFailedAttempt($pdo, $keys['ip'], 20);
            return ['mode' => 'login', 'error' => 'E-mail ou senha incorretos.'];
        }

        if (password_needs_rehash($user['password_hash'], $algorithm)) {
            $statement = $pdo->prepare(
                'UPDATE users SET password_hash = :password_hash WHERE id = :id'
            );
            $statement->execute([
                'password_hash' => password_hash($password, $algorithm),
                'id' => $user['id'],
            ]);
        }

        if ((int) $user['totp_enabled'] === 1) {
            session_regenerate_id(true);
            unset($_SESSION['user']);
            $_SESSION['pending_2fa_user_id'] = (int) $user['id'];
            $_SESSION['pending_2fa_email'] = $user['email'];
            $_SESSION['pending_2fa_expires'] = time() + TWO_FACTOR_CHALLENGE_LIMIT;
            $_SESSION['_started_at'] = time();
            $_SESSION['_last_activity'] = time();
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            redirect('./');
        }

        clearFailedAttempts($pdo, $keys);
        completeAuthentication($user);
    }

    http_response_code(400);

    return ['mode' => $mode, 'error' => 'Não foi possível processar sua solicitação.'];
}

$mode = ($_GET['mode'] ?? '') === 'register' ? 'register' : 'login';
$errorMessage = '';
$noticeMessage = (string) ($_SESSION['notice'] ?? '');
unset($_SESSION['notice']);
$recoveryCodes = $_SESSION['recovery_codes_flash'] ?? [];
unset($_SESSION['recovery_codes_flash']);
$loginSucceeded = $noticeMessage === 'Login realizado com sucesso.';
$currentUser = $_SESSION['user'] ?? null;
$expiredChallenge = isset($_SESSION['pending_2fa_user_id'])
    && (int) ($_SESSION['pending_2fa_expires'] ?? 0) < time();
if ($expiredChallenge) {
    unset(
        $_SESSION['pending_2fa_user_id'],
        $_SESSION['pending_2fa_email'],
        $_SESSION['pending_2fa_expires']
    );
    $errorMessage = 'A verificação em duas etapas expirou. Entre novamente.';
}
$pendingTwoFactor = isset($_SESSION['pending_2fa_user_id']);
$totpSecret = '';
$totpEnabled = false;
$totpPending = false;

try {
    $pdo = getDatabase();
    $postResult = processPost($pdo);
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $mode = $postResult['mode'];
        $errorMessage = $postResult['error'];
    }
    if ($currentUser) {
        $statement = $pdo->prepare(
            'SELECT totp_secret, totp_pending_secret, totp_enabled
             FROM users WHERE id = :id'
        );
        $statement->execute(['id' => $currentUser['id']]);
        $totpState = $statement->fetch() ?: [];
        $totpEnabled = (int) ($totpState['totp_enabled'] ?? 0) === 1;
        $totpPending = !$totpEnabled && !empty($totpState['totp_pending_secret']);
        if ($totpPending) {
            $totpSecret = decryptTotpSecret(
                (string) $totpState['totp_pending_secret'],
                getTotpEncryptionKey(getDatabaseDriver($pdo), getDatabasePath())
            );
        }
    }
} catch (PDOException $exception) {
    error_log('Falha no banco de dados da aplicação de login: ' . $exception->getMessage());
    http_response_code(503);
    $errorMessage = 'O serviço está temporariamente indisponível. Tente novamente mais tarde.';
} catch (RuntimeException $exception) {
    error_log('Configuração incompleta da aplicação de login: ' . $exception->getMessage());
    http_response_code(503);
    $errorMessage = 'O serviço está temporariamente indisponível. Tente novamente mais tarde.';
}

$currentUser = $_SESSION['user'] ?? null;
$pendingTwoFactor = isset($_SESSION['pending_2fa_user_id']);
$csrfToken = getCsrfToken();
?>
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#ffffff">
    <title><?= $currentUser ? 'Sua conta' : ($mode === 'register' ? 'Criar conta' : 'Entrar') ?> — Aster</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
<div class="ambient-scene" aria-hidden="true">
    <span class="bubble bubble-one"></span>
    <span class="bubble bubble-two"></span>
    <span class="bubble bubble-three"></span>
    <span class="bubble bubble-four"></span>
</div>
<header class="site-header">
    <a class="brand" href="./" aria-label="Aster, página inicial">
        <span>aster</span>
    </a>
    <nav class="header-links" aria-label="Navegação principal">
        <a href="./?mode=login" <?= $mode === 'login' ? 'aria-current="page"' : '' ?>>Entrar</a>
        <a href="./?mode=register" <?= $mode === 'register' ? 'aria-current="page"' : '' ?>>Criar conta</a>
        <a class="header-help" href="mailto:suporte@aster.local">Suporte</a>
    </nav>
</header>
<main class="page-shell">
    <section class="visual-panel" aria-label="Bem-vindo à Aster">
        <div class="visual-copy">
            <span class="eyebrow"><?= $currentUser ? 'SEU ESPAÇO PESSOAL' : ($mode === 'register' ? 'JÁ FAZ PARTE DA ASTER?' : 'NOVO POR AQUI?') ?></span>
            <h1><?= $currentUser ? 'Que bom ter você por aqui!' : ($mode === 'register' ? 'Bem-vindo de volta!' : 'Seu próximo capítulo começa aqui.') ?></h1>
            <p><?= $currentUser ? 'Seu próximo capítulo começa quando quiser.' : ($mode === 'register' ? 'Entre na sua conta e continue de onde parou.' : 'Crie seu acesso e comece uma nova jornada com a gente.') ?></p>
            <?php if (!$currentUser): ?>
                <a class="side-action" href="<?= $mode === 'register' ? './?mode=login' : './?mode=register' ?>">
                    <?= $mode === 'register' ? 'Já tenho uma conta' : 'Começar agora' ?>
                    <span aria-hidden="true">→</span>
                </a>
            <?php endif; ?>
        </div>
        <div class="visual-copy">
            <div class="artwork" aria-hidden="true">
                <span class="artwork-orbit artwork-orbit-one"></span>
                <span class="artwork-orbit artwork-orbit-two"></span>
                <span class="artwork-orbit artwork-orbit-three"></span>
                <span class="artwork-mark"></span>
                <span class="artwork-dot artwork-dot-one"></span>
                <span class="artwork-dot artwork-dot-two"></span>
                <span class="artwork-dot artwork-dot-three"></span>
            </div>
        </div>
    </section>

    <section class="form-panel">
        <div class="form-wrap">
            <?php if ($currentUser): ?>
                <?php if ($loginSucceeded): ?>
                    <div class="success-mark" aria-hidden="true">
                        <span class="success-ring"></span>
                        <svg viewBox="0 0 48 48" focusable="false">
                            <path d="m13 25 7 7 15-16"></path>
                        </svg>
                        <span class="success-dots">
                            <i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i>
                        </span>
                    </div>
                <?php endif; ?>
                <span class="eyebrow eyebrow-purple">ÁREA SEGURA</span>
                <h2><?= $loginSucceeded ? 'Login confirmado!' : 'Que bom ter você aqui.' ?></h2>
                <p class="form-intro">Você entrou como <strong><?= escape((string) $currentUser['email']) ?></strong>.</p>
                <?php if ($noticeMessage !== ''): ?>
                    <div class="alert alert-success" role="status"><?= escape($noticeMessage) ?></div>
                <?php endif; ?>
                <?php if ($errorMessage !== ''): ?>
                    <div class="alert alert-error" role="alert"><?= escape($errorMessage) ?></div>
                <?php endif; ?>
                <?php if ($recoveryCodes): ?>
                    <div class="recovery-box" role="status">
                        <strong>Guarde seus códigos de recuperação</strong>
                        <p>Cada código pode ser usado uma única vez. Eles não serão exibidos novamente.</p>
                        <ul class="recovery-list">
                            <?php foreach ($recoveryCodes as $code): ?>
                                <li><code><?= escape($code) ?></code></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                <?php if ($totpEnabled): ?>
                    <p class="form-intro security-status">Autenticador ativo. Seus próximos acessos exigirão um código de seis dígitos.</p>
                    <form method="post" action="./" class="security-form">
                        <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                        <input type="hidden" name="action" value="disable_totp">
                        <label for="disable-password">Confirme sua senha para desativar</label>
                        <div class="input-wrap">
                            <input id="disable-password" name="password" type="password" autocomplete="current-password" placeholder="Sua senha atual" maxlength="1024" required>
                        </div>
                        <label for="disable-code">Código do autenticador ou de recuperação</label>
                        <div class="input-wrap">
                            <input id="disable-code" name="totp_code" type="text" autocomplete="one-time-code" placeholder="Código de verificação" maxlength="64" required>
                        </div>
                        <button class="button button-secondary" type="submit">Desativar 2 etapas</button>
                    </form>
                <?php elseif ($totpPending): ?>
                    <div class="setup-box">
                        <strong>Adicione ao seu aplicativo autenticador</strong>
                        <p>Cadastre uma chave TOTP manual no Google Authenticator, Microsoft Authenticator ou app compatível.</p>
                        <code class="totp-secret"><?= escape($totpSecret) ?></code>
                        <p>Conta: <?= escape((string) $currentUser['email']) ?> · Aster · 6 dígitos · 30 segundos</p>
                        <form method="post" action="./" class="security-form">
                            <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                            <input type="hidden" name="action" value="confirm_totp">
                            <label for="setup-code">Digite o código gerado pelo aplicativo</label>
                            <div class="input-wrap">
                                <input id="setup-code" name="totp_code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" placeholder="000000" maxlength="6" required>
                            </div>
                            <button class="button button-primary" type="submit">Ativar verificação</button>
                        </form>
                        <form method="post" action="./" class="cancel-setup">
                            <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                            <input type="hidden" name="action" value="cancel_totp">
                            <button class="text-button" type="submit">Cancelar configuração</button>
                        </form>
                    </div>
                <?php else: ?>
                    <p class="form-intro security-status">Proteja sua conta com um código temporário do aplicativo autenticador.</p>
                    <form method="post" action="./" class="security-form">
                        <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                        <input type="hidden" name="action" value="start_totp">
                        <button class="button button-secondary" type="submit">Configurar verificação em 2 etapas</button>
                    </form>
                <?php endif; ?>
                <form method="post" action="./" class="logout-form">
                    <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="button button-secondary" type="submit">Sair da conta</button>
                </form>
            <?php elseif ($pendingTwoFactor): ?>
                <span class="eyebrow eyebrow-purple">SEGUNDA ETAPA</span>
                <h2>Confirme que é você.</h2>
                <p class="form-intro">Digite o código atual do seu aplicativo autenticador ou use um código de recuperação.</p>
                <?php if ($errorMessage !== ''): ?>
                    <div class="alert alert-error" role="alert"><?= escape($errorMessage) ?></div>
                <?php endif; ?>
                <form method="post" action="./" class="auth-form">
                    <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                    <input type="hidden" name="action" value="verify_2fa">
                    <label for="login-totp-code">Código de verificação</label>
                    <div class="input-wrap">
                        <input id="login-totp-code" name="totp_code" type="text" autocomplete="one-time-code" placeholder="Código de 6 dígitos ou de recuperação" maxlength="64" required autofocus>
                    </div>
                    <button class="button button-primary" type="submit">
                        <span class="button-label">Confirmar e entrar</span>
                        <span class="button-dots" aria-hidden="true"><i></i><i></i><i></i></span>
                    </button>
                </form>
                <form method="post" action="./" class="cancel-setup">
                    <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                    <input type="hidden" name="action" value="cancel_2fa">
                    <button class="text-button" type="submit">Cancelar e voltar</button>
                </form>
            <?php else: ?>
                <span class="eyebrow eyebrow-purple"><?= $mode === 'register' ? 'SEU COMEÇO NA ASTER' : 'ACESSO À SUA CONTA' ?></span>
                <h2><?= $mode === 'register' ? 'Que bom ter você aqui!' : 'Bem-vindo de volta!' ?></h2>
                <p class="form-intro">
                    <?= $mode === 'register' ? 'Crie sua conta e comece uma nova jornada.' : 'Entre e continue exatamente de onde parou.' ?>
                </p>

                <?php if ($noticeMessage !== ''): ?>
                    <div class="alert alert-success" role="status"><?= escape($noticeMessage) ?></div>
                <?php endif; ?>
                <?php if ($errorMessage !== ''): ?>
                    <div class="alert alert-error" role="alert"><?= escape($errorMessage) ?></div>
                <?php endif; ?>

                <form method="post" action="<?= $mode === 'register' ? './?mode=register' : './' ?>" class="auth-form">
                    <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
                    <input type="hidden" name="action" value="<?= escape($mode) ?>">

                    <label for="email">E-mail</label>
                    <div class="input-wrap">
                        <input
                            id="email"
                            name="email"
                            type="email"
                            autocomplete="email"
                            placeholder="<?= $mode === 'register' ? 'Seu melhor e-mail' : 'Digite seu e-mail' ?>"
                            maxlength="254"
                            value="<?= escape((string) ($_POST['email'] ?? '')) ?>"
                            required
                        >
                    </div>

                    <div class="label-row">
                        <label for="password">Senha</label>
                        <?php if ($mode === 'login'): ?>
                            <span class="field-hint">Mínimo de 12 caracteres</span>
                        <?php endif; ?>
                    </div>
                    <div class="input-wrap">
                        <input
                            id="password"
                            name="password"
                            type="password"
                            autocomplete="<?= $mode === 'register' ? 'new-password' : 'current-password' ?>"
                            placeholder="<?= $mode === 'register' ? 'Crie uma senha segura' : 'Digite sua senha' ?>"
                            minlength="<?= $mode === 'register' ? '12' : '1' ?>"
                            maxlength="1024"
                            required
                        >
                        <button class="password-toggle" type="button" aria-label="Mostrar senha" aria-pressed="false">Mostrar</button>
                    </div>

                    <?php if ($mode === 'register'): ?>
                        <p class="password-hint">Use pelo menos 12 caracteres para proteger sua conta.</p>
                        <label for="password_confirmation">Confirme sua senha</label>
                        <div class="input-wrap">
                            <input
                                id="password_confirmation"
                                name="password_confirmation"
                                type="password"
                                autocomplete="new-password"
                                placeholder="Digite a senha novamente"
                                minlength="12"
                                maxlength="1024"
                                required
                            >
                        </div>
                    <?php endif; ?>

                    <button class="button button-primary" type="submit">
                        <span class="button-label"><?= $mode === 'register' ? 'Criar minha conta' : 'Entrar com segurança' ?></span>
                        <span class="button-dots" aria-hidden="true"><i></i><i></i><i></i></span>
                    </button>
                </form>

                <p class="privacy-note">Seus dados são protegidos com segurança.</p>
            <?php endif; ?>
        </div>
        <footer class="form-footer">© <?= date('Y') ?> Aster <span>·</span> Feito para você.</footer>
    </section>
</main>
<script>
document.querySelectorAll('.password-toggle').forEach((button) => {
    button.addEventListener('click', () => {
        const input = button.parentElement.querySelector('input');
        const showing = input.type === 'password';
        input.type = showing ? 'text' : 'password';
        button.textContent = showing ? 'Ocultar' : 'Mostrar';
        button.setAttribute('aria-label', showing ? 'Ocultar senha' : 'Mostrar senha');
        button.setAttribute('aria-pressed', String(showing));
    });
});

document.querySelectorAll('.auth-form').forEach((form) => {
    form.addEventListener('submit', () => {
        const submitButton = form.querySelector('button[type="submit"]');
        if (!submitButton) return;
        submitButton.classList.add('is-loading');
        submitButton.setAttribute('aria-busy', 'true');
        submitButton.disabled = true;
        submitButton.querySelector('.button-label').textContent = 'Só um instante';
    });
});
</script>
</body>
</html>
