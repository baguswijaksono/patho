<?php

declare(strict_types=1); // Enable strict typing

require_once 'verify.php';
require_once 'db.php';

$limit = 10;
$page = isset($_GET['page']) ? intval($_GET['page']) : 1;
$offset = ($page - 1) * $limit;
$search = isset($_GET['search']) ? trim($_GET['search']) : '';

// Prepare the search query if there is a search term
$searchSql = '';
if ($search) {
    $searchSql = " WHERE title LIKE :search OR description LIKE :search OR severity LIKE :search";
}

// Get total records for pagination
$totalStmt = $conn->prepare("SELECT COUNT(*) FROM vulnerabilities" . $searchSql);
if ($search) {
    $totalStmt->bindValue(':search', '%' . $search . '%', PDO::PARAM_STR);
}
$totalStmt->execute();
$totalRecords = $totalStmt->fetchColumn();
$totalPages = ceil($totalRecords / $limit);

// Fetch vulnerabilities based on search and pagination
$stmt = $conn->prepare("SELECT * FROM vulnerabilities" . $searchSql . " LIMIT :limit OFFSET :offset");
if ($search) {
    $stmt->bindValue(':search', '%' . $search . '%', PDO::PARAM_STR);
}
$stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
$stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$vulnerabilities = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!-- Search Form -->
<form method="GET" action="">
    <input type="text" name="search" placeholder="Search vulnerabilities" value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
    <button type="submit" class="btn btn-primary">Search</button>
</form>

<!-- Table Display -->
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
        <?php if ($vulnerabilities): ?>
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
        <?php else: ?>
            <tr>
                <td colspan="6">No vulnerabilities found.</td>
            </tr>
        <?php endif; ?>
    </tbody>
</table>

<!-- Pagination -->
<div class="pagination">
    <?php if ($page > 1): ?>
        <a href="?page=<?php echo $page - 1; ?>&search=<?php echo urlencode($search); ?>" class="btn btn-secondary">Previous</a>
    <?php endif; ?>

    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
        <a href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>" class="btn btn-secondary <?php echo $i === $page ? 'active' : ''; ?>">
            <?php echo $i; ?>
        </a>
    <?php endfor; ?>

    <?php if ($page < $totalPages): ?>
        <a href="?page=<?php echo $page + 1; ?>&search=<?php echo urlencode($search); ?>" class="btn btn-secondary">Next</a>
    <?php endif; ?>
</div>

<a href="import.php" class="btn btn-primary">Import</a>
