```php
<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/PHPMailer-master/src/Exception.php';
require_once __DIR__ . '/PHPMailer-master/src/PHPMailer.php';
require_once __DIR__ . '/PHPMailer-master/src/SMTP.php';

$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = 'YOUR_GMAIL@gmail.com';
    $mail->Password   = 'YOUR_16_CHARACTER_APP_PASSWORD';
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;

    $mail->setFrom('YOUR_GMAIL@gmail.com', 'LegacyVault');
    $mail->addAddress('YOUR_GMAIL@gmail.com');

    $mail->Subject = 'LegacyVault SMTP Test';
    $mail->Body    = 'Your email configuration is working!';

    $mail->send();
    echo 'SUCCESS: Test email sent.';
} catch (Exception $e) {
    echo 'EMAIL ERROR: ' . htmlspecialchars($mail->ErrorInfo);
}
