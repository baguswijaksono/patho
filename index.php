<?php

declare(strict_types=1); // Enable strict typing

require_once 'verify.php';
require_once 'db.php';

$limit = 10;
$page = isset($_GET['page']) ? intval($_GET['page']) : 1;
$offset = ($page - 1) * $limit;
$search = isset($_GET['search']) ? trim($_GET['search']) : '';

// Initialize filters
$severityFilter = isset($_GET['severity']) && $_GET['severity'] !== '' ? $_GET['severity'] : null;
$statusFilter = isset($_GET['status']) && $_GET['status'] !== '' ? $_GET['status'] : null;

// Build the WHERE clause
$searchSql = ' WHERE 1=1';
if ($search) {
    $searchSql .= " AND (title LIKE :search OR description LIKE :search OR severity LIKE :search)";
}
if ($severityFilter) {
    $searchSql .= " AND severity = :severity";
}
if ($statusFilter) {
    $searchSql .= " AND status = :status";
}

// Get total records for pagination
$totalStmt = $conn->prepare("SELECT COUNT(*) FROM vulnerabilities" . $searchSql);

if ($search) {
    $totalStmt->bindValue(':search', '%' . $search . '%', PDO::PARAM_STR);
}
if ($severityFilter) {
    $totalStmt->bindValue(':severity', $severityFilter, PDO::PARAM_STR);
}
if ($statusFilter) {
    $totalStmt->bindValue(':status', $statusFilter, PDO::PARAM_STR);
}
$totalStmt->execute();
$totalRecords = $totalStmt->fetchColumn();
$totalPages = ceil($totalRecords / $limit);

// Fetch vulnerabilities based on search, filters, and pagination
$stmt = $conn->prepare("SELECT * FROM vulnerabilities" . $searchSql . " LIMIT :limit OFFSET :offset");

if ($search) {
    $stmt->bindValue(':search', '%' . $search . '%', PDO::PARAM_STR);
}
if ($severityFilter) {
    $stmt->bindValue(':severity', $severityFilter, PDO::PARAM_STR);
}
if ($statusFilter) {
    $stmt->bindValue(':status', $statusFilter, PDO::PARAM_STR);
}
$stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
$stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$vulnerabilities = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!-- Search and Filter Form -->
<form method="GET" action="">
    <input type="text" name="search" placeholder="Search vulnerabilities" value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">

    <!-- Filter by Severity -->
    <select name="severity">
        <option value="">All Severities</option>
        <option value="Low" <?php echo isset($_GET['severity']) && $_GET['severity'] == 'Low' ? 'selected' : ''; ?>>Low</option>
        <option value="Medium" <?php echo isset($_GET['severity']) && $_GET['severity'] == 'Medium' ? 'selected' : ''; ?>>Medium</option>
        <option value="High" <?php echo isset($_GET['severity']) && $_GET['severity'] == 'High' ? 'selected' : ''; ?>>High</option>
        <option value="Critical" <?php echo isset($_GET['severity']) && $_GET['severity'] == 'Critical' ? 'selected' : ''; ?>>Critical</option>
    </select>

    <!-- Filter by Status -->
    <select name="status">
        <option value="">All Statuses</option>
        <option value="Open" <?php echo isset($_GET['status']) && $_GET['status'] == 'Open' ? 'selected' : ''; ?>>Open</option>
        <option value="Resolved" <?php echo isset($_GET['status']) && $_GET['status'] == 'Resolved' ? 'selected' : ''; ?>>Resolved</option>
        <option value="Closed" <?php echo isset($_GET['status']) && $_GET['status'] == 'Closed' ? 'selected' : ''; ?>>Closed</option>
    </select>

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
        <a href="?page=<?php echo $page - 1; ?>&search=<?php echo urlencode($search); ?>&severity=<?php echo urlencode($severityFilter); ?>&status=<?php echo urlencode($statusFilter); ?>" class="btn btn-secondary">Previous</a>
    <?php endif; ?>

    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
        <a href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>&severity=<?php echo urlencode($severityFilter); ?>&status=<?php echo urlencode($statusFilter); ?>" class="btn btn-secondary <?php echo $i === $page ? 'active' : ''; ?>">
            <?php echo $i; ?>
        </a>
    <?php endfor; ?>

    <?php if ($page < $totalPages): ?>
        <a href="?page=<?php echo $page + 1; ?>&search=<?php echo urlencode($search); ?>&severity=<?php echo urlencode($severityFilter); ?>&status=<?php echo urlencode($statusFilter); ?>" class="btn btn-secondary">Next</a>
    <?php endif; ?>
</div>

<a href="import.php" class="btn btn-primary">Import</a>
