<?php
include 'db.php';

$stmt = $conn->query("SELECT * FROM vulnerabilities");
$vulnerabilities = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<table class="table">
    <thead>
        <tr>
            <th>Title</th>
            <th>Description</th>
            <th>Severity</th>
            <th>Reported Date</th>
            <th>Status</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($vulnerabilities as $vulnerability): ?>
            <tr>
                <td><?php echo htmlspecialchars($vulnerability['title']); ?></td>
                <td><?php echo htmlspecialchars($vulnerability['description']); ?></td>
                <td><?php echo htmlspecialchars($vulnerability['severity']); ?></td>
                <td><?php echo htmlspecialchars($vulnerability['reported_date']); ?></td>
                <td><?php echo htmlspecialchars($vulnerability['status']); ?></td>
                <td>
                    <a href="edit.php?id=<?php echo $vulnerability['id']; ?>">Edit</a> |
                    <a href="delete.php?id=<?php echo $vulnerability['id']; ?>" onclick="return confirm('Are you sure you want to delete this item?');">Delete</a>
                </td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>

<a href="import.php" class="btn btn-primary">Import</a>
