<?php
include 'db.php';

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['csvfile'])) {
    $file = $_FILES['csvfile']['tmp_name'];

    // Open the CSV file
    if (($handle = fopen($file, 'r')) !== FALSE) {
        // Skip the header row
        fgetcsv($handle);

        // Prepare the SQL statement
        $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (:title, :description, :severity, :status)");

        // Read each row of the CSV
        while (($data = fgetcsv($handle)) !== FALSE) {
            $title = $data[1];          // Assuming the columns match the order: ID, Title, Description, Severity, Reported Date, Status
            $description = $data[2];
            $severity = $data[3];
            $status = $data[5];

            // Bind parameters and execute the statement
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
