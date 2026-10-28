LEGACYVAULT — PHP + MYSQL STARTER
=================================

Features in this version
- Registration with password hashing
- Login with password + email OTP verification
- OTP expiry after 10 minutes and max 5 attempts
- OTP unlocks document vault for 10 minutes
- Upload/list/download/delete personal documents
- PDO prepared statements and per-user document ownership checks
- Upload storage separated from public pages; PDF/JPG/PNG only, max 5 MB

REQUIREMENTS
- XAMPP (Apache + PHP + MySQL/MariaDB)
- Composer (for PHPMailer email delivery)
- VS Code

SETUP
1. Extract the project folder as C:\xampp\htdocs\LegacyVault (folder name should be LegacyVault).
2. Start Apache and MySQL from XAMPP Control Panel.
3. Open http://localhost/phpmyadmin. Import database/legacyvault.sql.
   This creates the legacyvault database and required tables.
4. Open config/config.php and check DB_HOST, DB_NAME, DB_USER, DB_PASS.
   Default XAMPP settings are root with an empty password on many local installs.
5. Install PHPMailer: open Terminal in the LegacyVault project folder and run:
      composer require phpmailer/phpmailer
6. Configure SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_EMAIL,
   and SMTP_FROM_NAME in config/config.php. For Gmail, enable 2-Step Verification
   and create an App Password. Never put your normal Gmail password in this file.
7. If your folder is not named LegacyVault, update BASE_URL in config/config.php.
8. Open http://localhost/LegacyVault/index.html and choose Register.
9. Create an account, log in, enter the email OTP, then open Documents.
10. Upload a test PDF/JPG/PNG and test download/delete.

IMPORTANT
- Do not open PHP files by double-clicking or using Live Server. PHP needs Apache; use localhost.
- Email OTP will not work until PHPMailer and SMTP are configured. The app does not reveal OTPs on screen.
- This version implements email OTP as the second step. Device fingerprint/Face ID support uses WebAuthn/passkeys and is not yet implemented here. Browser biometric checks must be verified by a server; a visual fingerprint button alone is not secure.
- This is an academic prototype, not production-ready storage for sensitive personal documents. Before real-world use, add HTTPS, encryption at rest, rate limiting, security review, backup/recovery, and a legally sound emergency-access process.
- Old static beneficiary/messages/profile pages are retained as UI placeholders; the registration, login, dashboard, and document vault are the connected backend milestone.
