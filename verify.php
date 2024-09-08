<?php

session_start();

// Check if user is authenticated
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    header("Location: login.php");
    exit();
}