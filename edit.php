<?php
include 'db.php';

if (!isset($_GET['id'])) {
    header('Location: index.php');
    exit();
}

$id = intval($_GET['id']);
$stmt = $conn->prepare("SELECT * FROM vulnerabilities WHERE id = :id");
$stmt->bindParam(':id', $id);
$stmt->execute();
$vulnerability = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$vulnerability) {
    header('Location: index.php');
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $title = $_POST['title'];
    $description = $_POST['description'];
    $severity = $_POST['severity'];
    $status = $_POST['status'];

    $stmt = $conn->prepare("UPDATE vulnerabilities SET title = :title, description = :description, severity = :severity, status = :status WHERE id = :id");
    $stmt->bindParam(':title', $title);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':severity', $severity);
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':id', $id);
    $stmt->execute();

    header('Location: index.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Vulnerability</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2>Edit Vulnerability</h2>
        <form method="post" action="edit.php?id=<?php echo $vulnerability['id']; ?>">
            <div class="form-group">
                <label for="title">Title</label>
                <input type="text" class="form-control" id="title" name="title" value="<?php echo htmlspecialchars($vulnerability['title']); ?>" required>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <textarea class="form-control" id="description" name="description" required><?php echo htmlspecialchars($vulnerability['description']); ?></textarea>
            </div>
            <div class="form-group">
                <label for="severity">Severity</label>
                <select class="form-control" id="severity" name="severity">
                    <option value="Low" <?php echo ($vulnerability['severity'] == 'Low') ? 'selected' : ''; ?>>Low</option>
                    <option value="Medium" <?php echo ($vulnerability['severity'] == 'Medium') ? 'selected' : ''; ?>>Medium</option>
                    <option value="High" <?php echo ($vulnerability['severity'] == 'High') ? 'selected' : ''; ?>>High</option>
                </select>
            </div>
            <div class="form-group">
                <label for="status">Status</label>
                <select class="form-control" id="status" name="status">
                    <option value="Open" <?php echo ($vulnerability['status'] == 'Open') ? 'selected' : ''; ?>>Open</option>
                    <option value="Closed" <?php echo ($vulnerability['status'] == 'Closed') ? 'selected' : ''; ?>>Closed</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">Save Changes</button>
        </form>
    </div>
</body>
</html>
