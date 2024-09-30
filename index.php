<?php

declare(strict_types=1);

$routes = [
    'GET' => [],
    'POST' => [],
    'PUT' => [],
    'DELETE' => [],
];

function conn()
{
    $servername = "localhost";
    $username = "phpmyadmin";
    $password = "your_password";
    $dbname = "vulnerability_tracker";
    $conn = new mysqli($servername, $username, $password, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    return $conn;
}

function middleware()
{
    session_start();

    if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
        header("Location: /login");
        exit();
    }
}

function login($error = null)
{
?>
    <!DOCTYPE html>
    <html>

    <head>
        <title>Login</title>
    </head>

    <body>
        <h2>Login</h2>
        <form method="post" action="/authenticate">
            <input type="password" name="password" placeholder="Enter password" required>
            <button type="submit">Login</button>
        </form>
        <?php if ($error): ?>
            <p><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
    </body>

    </html>
<?php
}

function authenticate()
{
    session_start();
    define('CORRECT_PASSWORD_HASH', password_hash('your-here', PASSWORD_DEFAULT));

    if (password_verify($_POST['password'], CORRECT_PASSWORD_HASH)) {
        $_SESSION['authenticated'] = true;
        header("Location: /");
        exit();
    } else {
        $error = "Invalid password.";
        login($error);
    }
}

function logout()
{
    session_start();
    session_unset();
    session_destroy();
    header("Location: /login");
    exit();
}

function export()
{
    middleware();
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment;filename="vulnerabilities.csv"');

    $output = fopen('php://output', 'w');
    fputcsv($output, array('ID', 'Title', 'Description', 'Severity', 'Reported Date', 'Status'));

    $conn = conn();
    $stmt = $conn->query("SELECT * FROM vulnerabilities");
    while ($row = $stmt->fetch_assoc()) {
        fputcsv($output, $row);
    }
    fclose($output);
}

function store()
{
    middleware();
    $conn = conn();
    $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (?, ?, ?, ?)");
    $stmt->bind_param('ssss', $_POST['title'], $_POST['description'], $_POST['severity'], $_POST['status']);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    returntohome();
}

function returntohome()
{
    header('Location: /');
    exit();
}

function create()
{
    middleware();
    echo '<form method="post" action="/store">';
    echo '<input type="text" name="title" placeholder="Title" required>';
    echo '<textarea name="description" placeholder="Description" required></textarea>';
    echo '<select name="severity">';
    echo '<option value="Low">Low</option>';
    echo '<option value="Medium">Medium</option>';
    echo '<option value="High">High</option>';
    echo '</select>';
    echo '<select name="status">';
    echo '<option value="Open">Open</option>';
    echo '<option value="Closed">Closed</option>';
    echo '</select>';
    echo '<button type="submit">Submit</button>';
    echo '</form>';
}

function importform()
{
    middleware();
    echo '<!DOCTYPE html>
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
    </html>';
}

function import()
{
    middleware();
    if (!isset($_FILES['csvfile'])) {
        echo "No file uploaded.";
        return;
    }

    $file = $_FILES['csvfile']['tmp_name'];
    $handle = fopen($file, 'r');
    if ($handle === FALSE) {
        echo "Error opening the file.";
        return;
    }

    fgetcsv($handle); // Skip the header row
    $conn = conn();
    $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (?, ?, ?, ?)");

    while (($data = fgetcsv($handle)) !== FALSE) {
        $title = $data[1];          // Assuming the columns match the order: ID, Title, Description, Severity, Reported Date, Status
        $description = $data[2];
        $severity = $data[3];
        $status = $data[5];
        $stmt->bind_param('ssss', $title, $description, $severity, $status);
        $stmt->execute();
    }

    fclose($handle);
    $stmt->close();
    $conn->close();
    echo "CSV data imported successfully!";
}

function editForm($id)
{
    middleware();
    $id = intval($id);
    $conn = conn();
    $result = $conn->query("SELECT * FROM vulnerabilities WHERE id = $id");

    if ($result->num_rows === 0) {
        returntohome();
    }

    $vulnerability = $result->fetch_assoc();
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
            <form method="post" action="/update/<?php echo $vulnerability['id']; ?>" enctype="application/x-www-form-urlencoded" onsubmit="event.preventDefault(); fetch(this.action, { method: 'PUT', body: new URLSearchParams(new FormData(this)) }).then(response => { if (response.ok) { window.location.href = '/'; } else { alert('Failed to update vulnerability'); } });">
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
<?php
}

function migrate()
{
    middleware();
    $conn = conn();
    $conn->query("CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        severity ENUM('Low', 'Medium', 'High') NOT NULL,
        status ENUM('Open', 'Closed') NOT NULL,
        reported_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    $conn->close();
    echo "Migration successful!";
}

function update($id)
{
    middleware();
    parse_str(file_get_contents("php://input"), $put_vars);
    $conn = conn();
    $stmt = $conn->prepare("UPDATE vulnerabilities SET title = ?, description = ?, severity = ?, status = ? WHERE id = ?");
    $stmt->bind_param('ssssi', $put_vars['title'], $put_vars['description'], $put_vars['severity'], $put_vars['status'], $id);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    exit();
    returntohome();
}

function destroy($id)
{
    middleware();
    $conn = conn();
    $stmt = $conn->prepare("DELETE FROM vulnerabilities WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    returntohome();
}

function get(string $path, callable $handler): void
{
    global $routes;
    $routes['GET'][$path] = $handler;
}

function post(string $path, callable $handler): void
{
    global $routes;
    $routes['POST'][$path] = $handler;
}

function put(string $path, callable $handler): void
{
    global $routes;
    $routes['PUT'][$path] = $handler;
}

function delete(string $path, callable $handler): void
{
    global $routes;
    $routes['DELETE'][$path] = $handler;
}


function dispatch(string $url, string $method): void
{
    global $routes;

    if (!isset($routes[$method])) {
        http_response_code(405);
        echo "Method $method Not Allowed";
        return;
    }

    foreach ($routes[$method] as $path => $handler) {
        if (preg_match("#^$path$#", $url, $matches)) {
            array_shift($matches);
            call_user_func_array($handler, $matches);
            return;
        }
    }

    http_response_code(404);
    handleNotFound();
}

function handleNotFound(): void
{
    echo "404 Not Found";
}

function listen(): void
{
    $url = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $method = $_SERVER['REQUEST_METHOD'];

    get('/', 'home');
    get('/login', 'login');
    get('/logout', 'logout');
    get('/export', 'export');
    post('/store', 'store');
    get('/create', 'create');
    get('/import', 'importform');
    post('/import', 'import');
    get('/edit/([\w-]+)', 'editForm');
    put('/update/([\w-]+)', 'update');
    delete('/destroy/([\w-]+)', 'destroy');
    get('/migrate', 'migrate');
    post('/authenticate', 'authenticate');

    dispatch($url, $method);
}

function home(): void
{
    middleware();
    $limit = 10;
    $page = isset($_GET['page']) ? intval($_GET['page']) : 1;
    $offset = ($page - 1) * $limit;
    $search = isset($_GET['search']) ? trim($_GET['search']) : '';

    // Initialize filters
    $severityFilter = isset($_GET['severity']) && $_GET['severity'] !== '' ? $_GET['severity'] : null;
    $statusFilter = isset($_GET['status']) && $_GET['status'] !== '' ? $_GET['status'] : null;

    // Build the WHERE clause
    $searchSql = ' WHERE 1=1';
    $params = [];
    if ($search) {
        $searchSql .= " AND (title LIKE ? OR description LIKE ? OR severity LIKE ?)";
        $params[] = '%' . $search . '%';
        $params[] = '%' . $search . '%';
        $params[] = '%' . $search . '%';
    }
    if ($severityFilter) {
        $searchSql .= " AND severity = ?";
        $params[] = $severityFilter;
    }
    if ($statusFilter) {
        $searchSql .= " AND status = ?";
        $params[] = $statusFilter;
    }

    // Get total records for pagination
    $conn = conn();
    $totalQuery = "SELECT COUNT(*) FROM vulnerabilities" . $searchSql;
    $totalStmt = $conn->prepare($totalQuery);

    // Bind params only if there are any
    if (!empty($params)) {
        $totalStmt->bind_param(str_repeat('s', count($params)), ...$params);
    }

    $totalStmt->execute();
    $totalStmt->bind_result($totalRecords);
    $totalStmt->fetch();
    $totalStmt->close();
    $totalPages = ceil($totalRecords / $limit);

    // Fetch vulnerabilities based on search, filters, and pagination
    $vulnQuery = "SELECT * FROM vulnerabilities" . $searchSql . " LIMIT ? OFFSET ?";
    $stmt = $conn->prepare($vulnQuery);

    // Add limit and offset to params
    $params[] = $limit;
    $params[] = $offset;

    // Bind the parameters (including integers for limit and offset)
    if (!empty($params)) {
        $stmt->bind_param(str_repeat('s', count($params) - 2) . 'ii', ...$params);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $vulnerabilities = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    $conn->close();
?>

    <!-- Search and Filter Form -->
    <form method="GET" action="">
        <input type="text" name="search" placeholder="Search vulnerabilities" value="<?php echo htmlspecialchars($search); ?>">

        <!-- Filter by Severity -->
        <select name="severity">
            <option value="">All Severities</option>
            <option value="Low" <?php echo $severityFilter === 'Low' ? 'selected' : ''; ?>>Low</option>
            <option value="Medium" <?php echo $severityFilter === 'Medium' ? 'selected' : ''; ?>>Medium</option>
            <option value="High" <?php echo $severityFilter === 'High' ? 'selected' : ''; ?>>High</option>
            <option value="Critical" <?php echo $severityFilter === 'Critical' ? 'selected' : ''; ?>>Critical</option>
        </select>

        <!-- Filter by Status -->
        <select name="status">
            <option value="">All Statuses</option>
            <option value="Open" <?php echo $statusFilter === 'Open' ? 'selected' : ''; ?>>Open</option>
            <option value="Resolved" <?php echo $statusFilter === 'Resolved' ? 'selected' : ''; ?>>Resolved</option>
            <option value="Closed" <?php echo $statusFilter === 'Closed' ? 'selected' : ''; ?>>Closed</option>
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
                            <a href="edit/<?php echo $vulnerability['id']; ?>">Edit</a> |
                            <a href="#" onclick="event.preventDefault(); if (confirm('Are you sure you want to delete this item?')) { fetch('/destroy/<?php echo $vulnerability['id']; ?>', { method: 'DELETE' }).then(response => { if (response.ok) { window.location.href = '/'; } else { alert('Failed to delete vulnerability'); } }); }">Delete</a>
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
            <a href="<?php echo generateUrl($page - 1); ?>" class="btn btn-secondary">Previous</a>
        <?php endif; ?>

        <?php for ($i = 1; $i <= $totalPages; $i++): ?>
            <a href="<?php echo generateUrl($i); ?>" class="btn btn-secondary <?php echo $i === $page ? 'active' : ''; ?>">
                <?php echo $i; ?>
            </a>
        <?php endfor; ?>

        <?php if ($page < $totalPages): ?>
            <a href="<?php echo generateUrl($page + 1); ?>" class="btn btn-secondary">Next</a>
        <?php endif; ?>
    </div>

    <a href="/import" class="btn btn-primary">Import</a>
    <a href="/create" class="btn btn-primary">Create</a>
    <a href="/export" class="btn btn-primary">Export</a>
    <a href="/migrate" class="btn btn-primary">Migrate</a>
    <a href="/logout" class="btn btn-primary">Logout</a>

<?php
}

function generateUrl($page)
{
    global $search, $severityFilter, $statusFilter;
    return "?page=$page" .
        ($search ? "&search=" . urlencode($search) : '') .
        ($severityFilter ? "&severity=" . urlencode($severityFilter) : '') .
        ($statusFilter ? "&status=" . urlencode($statusFilter) : '');
}

listen();
