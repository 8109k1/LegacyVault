<?php
require_once __DIR__ . '/../includes/bootstrap.php';
if (!empty($_SESSION['user_id'])) { header('Location: dashboard.php'); exit; }
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $name = trim((string)($_POST['full_name'] ?? ''));
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $phone = trim((string)($_POST['phone'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $confirm = (string)($_POST['confirm_password'] ?? '');
    if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $phone === '') $error = 'Enter valid details in all fields.';
    elseif (strlen($password) < 8) $error = 'Use a password with at least 8 characters.';
    elseif ($password !== $confirm) $error = 'The passwords do not match.';
    else {
        try {
            $stmt = db()->prepare('INSERT INTO users (full_name,email,phone,password_hash) VALUES (?,?,?,?)');
            $stmt->execute([$name,$email,$phone,password_hash($password, PASSWORD_DEFAULT)]);
            set_flash('Account created. Sign in to verify your email and access your vault.', 'success');
            header('Location: login.php'); exit;
        } catch (PDOException $ex) {
            $error = $ex->getCode() === '23000' ? 'An account with this email already exists.' : 'Could not create your account. Check the database setup.';
        }
    }
}
$flash = get_flash();
?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Create account | LegacyVault</title><link rel="stylesheet" href="../css/style.css"></head>
<body class="auth-page"><div class="auth-shell"><a class="brand auth-brand" href="../index.html"><span class="brand-icon">▣</span> LegacyVault</a><div class="auth-card register-card"><div class="auth-logo">▣</div><h1>Create an Account</h1><p>Start organizing your digital legacy.</p>
<?php if ($flash): ?><div class="notice <?=e($flash['type'])?>"><?=e($flash['message'])?></div><?php endif; ?><?php if ($error): ?><div class="notice error"><?=e($error)?></div><?php endif; ?>
<form method="post" action="register.php"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><label>Full Name<input name="full_name" type="text" placeholder="Enter your full name" maxlength="120" required value="<?=e($_POST['full_name'] ?? '')?>"></label><label>Email Address<input name="email" type="email" placeholder="Enter your email" maxlength="190" required value="<?=e($_POST['email'] ?? '')?>"></label><label>Phone Number<input name="phone" type="tel" placeholder="Enter your phone number" maxlength="30" required value="<?=e($_POST['phone'] ?? '')?>"></label><label>Password<input name="password" type="password" placeholder="At least 8 characters" minlength="8" required></label><label>Confirm Password<input name="confirm_password" type="password" placeholder="Re-enter your password" minlength="8" required></label><button class="btn btn-primary full" type="submit">Create Account</button></form><p class="auth-footer">Already have an account? <a href="login.php">Login</a></p></div></div></body></html>
