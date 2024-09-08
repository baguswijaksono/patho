<?php

declare(strict_types=1);

require_once 'auth/verify.php';
require_once 'db.php';

if (!isset($_GET['id'])) {
    header('Location: index.php');
    exit();
}

$id = intval($_GET['id']);

$stmt = $conn->prepare("DELETE FROM vulnerabilities WHERE id = :id");
$stmt->bindParam(':id', $id);
$stmt->execute();

header('Location: index.php');
exit();
?>
