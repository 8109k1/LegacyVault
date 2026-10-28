<?php
require_once __DIR__ . '/../includes/bootstrap.php';
if (empty($_SESSION['pending_user_id'])) { header('Location: login.php'); exit; }
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf(); $otp = trim((string)($_POST['otp'] ?? '')); $uid = (int)$_SESSION['pending_user_id'];
    $stmt = db()->prepare('SELECT id,otp_hash,expires_at,attempts FROM login_otps WHERE user_id=? ORDER BY id DESC LIMIT 1'); $stmt->execute([$uid]); $record = $stmt->fetch();
    if (!$record || strtotime($record['expires_at']) < time()) { $error = 'This code has expired. Sign in again to request a new one.'; }
    elseif ((int)$record['attempts'] >= 5) { $error = 'Too many incorrect attempts. Sign in again to request a new code.'; }
    elseif (!preg_match('/^\d{6}$/',$otp) || !password_verify($otp,$record['otp_hash'])) { db()->prepare('UPDATE login_otps SET attempts=attempts+1 WHERE id=?')->execute([$record['id']]); $error = 'That code is incorrect. Try again.'; }
    else {
        $userStmt = db()->prepare('SELECT id,full_name,email FROM users WHERE id=?'); $userStmt->execute([$uid]); $user=$userStmt->fetch();
        if (!$user) { header('Location: login.php'); exit; }
        session_regenerate_id(true); $_SESSION['user_id']=(int)$user['id']; $_SESSION['user_name']=$user['full_name']; $_SESSION['user_email']=$user['email']; $_SESSION['documents_unlocked_until']=time()+600;
        db()->prepare('DELETE FROM login_otps WHERE user_id=?')->execute([$uid]); unset($_SESSION['pending_user_id'],$_SESSION['pending_user_name']);
        $next = ($_GET['next'] ?? $_POST['next'] ?? '') === 'documents' ? 'documents.php' : 'dashboard.php'; header('Location: '.$next); exit;
    }
}
?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Verify OTP | LegacyVault</title><link rel="stylesheet" href="../css/style.css"></head><body class="auth-page"><div class="auth-shell"><a class="brand auth-brand" href="../index.html"><span class="brand-icon">▣</span> LegacyVault</a><div class="auth-card"><div class="auth-logo">✉</div><h1>Verify your email</h1><p>Enter the 6-digit code sent to your registered email.</p><?php if ($error): ?><div class="notice error"><?=e($error)?></div><?php endif; ?><form method="post"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="next" value="<?=e($_GET['next'] ?? '')?>"><label>One-Time Password<input name="otp" type="text" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="000000" autocomplete="one-time-code" required autofocus></label><div class="security-note">For your security, the code expires after 10 minutes and is limited to 5 attempts. Document access is unlocked for 10 minutes after verification.</div><button class="btn btn-primary full" type="submit">Verify &amp; Continue</button></form><p class="auth-footer"><a href="logout.php">Cancel and return to login</a></p></div></div></body></html>
