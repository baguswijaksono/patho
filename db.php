<?php
$servername = "localhost";
$username = "phpmyadmin"; // Your MySQL username
$password = "your_password"; // Your MySQL password
$dbname = "vulnerability_tracker";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}
?>
