CREATE TABLE `vulnerabilities` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `severity` enum('Low','Medium','High') NOT NULL,
  `reported_date` datetime DEFAULT current_timestamp(),
  `status` enum('Open','Closed') DEFAULT 'Open'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;