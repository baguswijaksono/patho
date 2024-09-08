<?php

declare(strict_types=1);

require_once 'auth/verify.php';
require_once 'db.php';

header('Content-Type: text/csv');
header('Content-Disposition: attachment;filename="vulnerabilities.csv"');

$output = fopen('php://output', 'w');
fputcsv($output, array('ID', 'Title', 'Description', 'Severity', 'Reported Date', 'Status'));

$stmt = $conn->query("SELECT * FROM vulnerabilities");
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    fputcsv($output, $row);
}
fclose($output);
?>
