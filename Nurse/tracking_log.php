<?php
session_start();
require '../Config/database.php';
if (!isset($_SESSION['UID'])) {
    die("Unauthorized. Please log in.");
}
$UID = $_SESSION['UID'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Tracking Log</title>
  <link rel="stylesheet" href="../Stylesheet/doctorForm.css" />
  <link rel="stylesheet" href="../Stylesheet/tracking.css" />
  <script src="https://kit.fontawesome.com/503ea13a85.js" crossorigin="anonymous"></script>
</head>
<body>
  <div class="sidebar">
    <a href="nurseDashboard.php"><i class="fa-solid fa-house fa-3x"></i></a>
    <a href="patientsList.php"><i class="fa-solid fa-hospital-user fa-3x"></i></a>
    <a href="tracking.php"><i class="fa-solid fa-clock fa-3x"></i></a>
    <a href="#"><i class="fa-solid fa-box fa-3x"></i></a>
  </div>

  <div class="main">
    <nav>
      <a href="nurseDashboard.php">Dashboard</a>
      <a href="tracking.php">Admission</a>
      <a href="#" class="active">Tracking Log</a>
      <a href="../Inventory/INVDASH.html">Inventory</a>
    </nav>
    <br>
    <div class="appointments-container">
      <h2>Tracking Log | <?php echo date('F d, Y'); ?></h2>
      <table class="appointments-table">
        <thead>
          <tr>            
            <th>School No.</th>
            <th>Name</th>
            <th>Start Time</th>
            <th>End Time</th>
            <th>Duration</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <?php
          try {
            $query = "SELECT t.trackingid,
                        u.schoolID as school_no,
                        CONCAT(COALESCE(u.fname, ''), ' ', COALESCE(u.lname, '')) as name,
                        t.trackingStart,
                        t.trackingEnd,
                        t.trackingStatusType as status
                      FROM tracking t
                      JOIN userInfo u ON t.UID = u.UID
                      ORDER BY t.trackingStart DESC";

            $stmt = $conn->prepare($query);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
              while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $startTime = new DateTime($row['trackingStart']);
                $endTime = $row['trackingEnd'] ? new DateTime($row['trackingEnd']) : null;
                $duration = '';
                
                if ($endTime) {
                    $interval = $startTime->diff($endTime);
                    $duration = sprintf(
                        '%dh %dm %ds',
                        $interval->h + ($interval->days * 24),
                        $interval->i,
                        $interval->s
                    );
                } else {
                    $duration = 'Ongoing';
                }                echo "<tr>";
                echo "<td>" . htmlspecialchars($row['school_no']) . "</td>";
                echo "<td>" . htmlspecialchars($row['name']) . "</td>";
                echo "<td>" . htmlspecialchars($startTime->format('Y-m-d H:i:s')) . "</td>";
                echo "<td>" . ($endTime ? htmlspecialchars($endTime->format('Y-m-d H:i:s')) : '-') . "</td>";
                echo "<td>" . htmlspecialchars($duration) . "</td>";
                echo "<td>" . htmlspecialchars($row['status']) . "</td>";
                echo "</tr>";
              }
            } else {              echo "<tr><td colspan='6' style='text-align: center;'>No tracking records found</td></tr>";
            }
          } catch (PDOException $e) {
            echo "<tr><td colspan='6' style='text-align: center; color: red;'>Error: " . $e->getMessage() . "</td></tr>";
          }
          ?>
        </tbody>
      </table>
    </div>
  </div>

  <i class="fa-regular fa-user" id="profile"></i>
</body>
</html>
