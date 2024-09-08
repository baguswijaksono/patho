<?php
session_start();
define('CORRECT_PASSWORD_HASH', password_hash('your-password-here', PASSWORD_DEFAULT));

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $password = $_POST['password'];
    if (password_verify($password, CORRECT_PASSWORD_HASH)) {
        $_SESSION['authenticated'] = true;
        header("Location: index.php"); 
        exit();
    } else {
        $error = "Invalid password.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="post" action="login.php">
        <input type="password" name="password" placeholder="Enter password" required>
        <button type="submit">Login</button>
    </form>
    <?php if (isset($error)): ?>
        <p><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
</body>
</html>
