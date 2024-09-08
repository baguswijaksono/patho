<?php

declare(strict_types=1);
require_once 'auth/verify.php';
require_once 'db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $title = $_POST['title'];
    $description = $_POST['description'];
    $severity = $_POST['severity'];
    $status = $_POST['status'];

    $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (:title, :description, :severity, :status)");
    $stmt->bindParam(':title', $title);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':severity', $severity);
    $stmt->bindParam(':status', $status);
    $stmt->execute();

    header("Location: index.php");
}
?>

<form method="post" action="create.php">
    <input type="text" name="title" placeholder="Title" required>
    <textarea name="description" placeholder="Description" required></textarea>
    <select name="severity">
        <option value="Low">Low</option>
        <option value="Medium">Medium</option>
        <option value="High">High</option>
    </select>
    <select name="status">
        <option value="Open">Open</option>
        <option value="Closed">Closed</option>
    </select>
    <button type="submit">Submit</button>
</form>
