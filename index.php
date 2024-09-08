<?php
include 'db.php';

// Set the number of records per page
$limit = 10; // Number of records per page

// Get the current page from query parameters, default to 1 if not set
$page = isset($_GET['page']) ? intval($_GET['page']) : 1;

// Calculate the offset for the SQL query
$offset = ($page - 1) * $limit;

// Fetch the total number of records
$totalStmt = $conn->query("SELECT COUNT(*) FROM vulnerabilities");
$totalRecords = $totalStmt->fetchColumn();
$totalPages = ceil($totalRecords / $limit);

// Fetch records for the current page
$stmt = $conn->prepare("SELECT * FROM vulnerabilities LIMIT :limit OFFSET :offset");
$stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
$stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
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

<!-- Pagination links -->
<div class="pagination">
    <?php if ($page > 1): ?>
        <a href="?page=<?php echo $page - 1; ?>" class="btn btn-secondary">Previous</a>
    <?php endif; ?>

    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
        <a href="?page=<?php echo $i; ?>" class="btn btn-secondary <?php echo $i === $page ? 'active' : ''; ?>">
            <?php echo $i; ?>
        </a>
    <?php endfor; ?>

    <?php if ($page < $totalPages): ?>
        <a href="?page=<?php echo $page + 1; ?>" class="btn btn-secondary">Next</a>
    <?php endif; ?>
</div>

<a href="import.php" class="btn btn-primary">Import</a>
