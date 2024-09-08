<?php

require_once 'auth/verify.php';
require_once 'db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['csvfile'])) {
    $file = $_FILES['csvfile']['tmp_name'];
    if (($handle = fopen($file, 'r')) !== FALSE) {
        fgetcsv($handle);
        $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (:title, :description, :severity, :status)");

        while (($data = fgetcsv($handle)) !== FALSE) {
            $title = $data[1];          // Assuming the columns match the order: ID, Title, Description, Severity, Reported Date, Status
            $description = $data[2];
            $severity = $data[3];
            $status = $data[5];
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':severity', $severity);
            $stmt->bindParam(':status', $status);
            $stmt->execute();
        }

        fclose($handle);
        echo "CSV data imported successfully!";
    } else {
        echo "Error opening the file.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Import CSV</title>
</head>
<body>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="csvfile" accept=".csv" required>
        <button type="submit">Upload and Import</button>
    </form>
</body>
</html>
