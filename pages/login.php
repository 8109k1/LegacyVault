<?php
require_once __DIR__ . '/../includes/bootstrap.php';
if (!empty($_SESSION['user_id'])) { header('Location: dashboard.php'); exit; }
$error = ''; $flash = get_flash();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $password = (string)($_POST['password'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') $error = 'Enter your email and password.';
    else {
        $stmt = db()->prepare('SELECT id,full_name,email,password_hash FROM users WHERE email = ? LIMIT 1'); $stmt->execute([$email]); $user = $stmt->fetch();
        if (!$user || !password_verify($password, $user['password_hash'])) $error = 'The email or password is incorrect.';
        else {
            $otp = (string)random_int(100000,999999);
            $hash = password_hash($otp, PASSWORD_DEFAULT);
            $pdo = db(); $pdo->prepare('DELETE FROM login_otps WHERE user_id = ?')->execute([$user['id']]);
            $pdo->prepare('INSERT INTO login_otps (user_id,otp_hash,expires_at) VALUES (?,?,DATE_ADD(NOW(), INTERVAL 10 MINUTE))')->execute([$user['id'],$hash]);
            $_SESSION['pending_user_id'] = (int)$user['id'];
            $_SESSION['pending_user_name'] = $user['full_name'];
            if (send_otp_email($user['email'], $user['full_name'], $otp)) { $next = ($_GET['next'] ?? '') === 'documents' ? '?next=documents' : ''; header('Location: verify-otp.php'.$next); exit; }
            // Don't display the OTP in the browser; it is only sent by configured SMTP.
            $pdo->prepare('DELETE FROM login_otps WHERE user_id = ?')->execute([$user['id']]);
            unset($_SESSION['pending_user_id'], $_SESSION['pending_user_name']);
            $error = 'We could not send the verification email. Configure SMTP in config/config.php and install PHPMailer, then try again.';
        }
    }
}
?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login | LegacyVault</title><link rel="stylesheet" href="../css/style.css"></head><body class="auth-page"><div class="auth-shell"><a class="brand auth-brand" href="../index.html"><span class="brand-icon">▣</span> LegacyVault</a><div class="auth-card"><div class="auth-logo">▣</div><h1>Welcome Back</h1><p>Sign in to your secure vault</p><?php if ($flash): ?><div class="notice <?=e($flash['type'])?>"><?=e($flash['message'])?></div><?php endif; ?><?php if ($error): ?><div class="notice error"><?=e($error)?></div><?php endif; ?><form method="post" action="login.php<?=($_GET['next'] ?? '') === 'documents' ? '?next=documents' : ''?>"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><label>Email Address<input name="email" type="email" placeholder="Enter your email" required autocomplete="username" value="<?=e($_POST['email'] ?? '')?>"></label><label>Password<input name="password" type="password" placeholder="Enter your password" required autocomplete="current-password"></label><div class="security-note">An email OTP is required after your password to unlock the document vault.</div><button class="btn btn-primary full" type="submit">Login &amp; Verify</button></form><p class="auth-footer">Don't have an account? <a href="register.php">Register</a></p></div></div></body></html>
