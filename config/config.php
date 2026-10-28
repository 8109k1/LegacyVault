<?php
// Local development settings. Update these for your computer and SMTP account.
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'legacyvault');
define('DB_USER', 'root');
define('DB_PASS', '');

// Configure SMTP to send real email OTPs. For Gmail, use an App Password (not your normal password).
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'your-email@gmail.com');
define('SMTP_PASSWORD', 'your-16-character-app-password');
define('SMTP_FROM_EMAIL', 'your-email@gmail.com');
define('SMTP_FROM_NAME', 'LegacyVault Security');

// Change this to the folder URL if your XAMPP folder has a different name.
define('BASE_URL', '/LegacyVault/pages');
