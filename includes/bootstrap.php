<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('LEGACYVAULT_SESSION');
    session_start();
}
require_once __DIR__ . '/../config/config.php';

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $pdo = new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4', DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}
function e(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}
function verify_csrf(): void {
    $sent = $_POST['csrf_token'] ?? '';
    if (!is_string($sent) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $sent)) {
        http_response_code(419); exit('Your session expired. Go back and try again.');
    }
}
function require_login(): void {
    if (empty($_SESSION['user_id'])) { header('Location: login.php'); exit; }
}
function require_document_otp(): void {
    require_login();
    if (empty($_SESSION['documents_unlocked_until']) || $_SESSION['documents_unlocked_until'] < time()) {
        unset($_SESSION['documents_unlocked_until']);
        header('Location: login.php?next=documents'); exit;
    }
}
function send_otp_email(string $to, string $name, string $otp): bool {
    $autoload = __DIR__ . '/../vendor/autoload.php';
    if (!file_exists($autoload)) return false;
    require_once $autoload;
    if (!class_exists(\PHPMailer\PHPMailer\PHPMailer::class)) return false;
    try {
        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($to, $name);
        $mail->isHTML(true);
        $mail->Subject = 'Your LegacyVault verification code';
        $mail->Body = '<p>Hello ' . e($name) . ',</p><p>Your LegacyVault one-time password is:</p><p style="font-size:28px;font-weight:bold;letter-spacing:6px">' . e($otp) . '</p><p>This code expires in 10 minutes. If you did not request it, ignore this email.</p>';
        $mail->AltBody = "Your LegacyVault OTP is $otp. It expires in 10 minutes.";
        $mail->send();
        return true;
    } catch (Throwable $ex) {
        error_log('LegacyVault email error: ' . $ex->getMessage());
        return false;
    }
}
function set_flash(string $message, string $type='info'): void { $_SESSION['flash'] = ['message'=>$message,'type'=>$type]; }
function get_flash(): ?array { $f = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); return $f; }
