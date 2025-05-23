<?php
session_start();
require '../Config/database.php';
if (!isset($_SESSION['UID'])) {
    die("Unauthorized. Please log in.");
}
$UID = $_SESSION['UID']
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Patient Tracking</title>  <link rel="stylesheet" href="../Stylesheet/doctorForm.css" />
  <link rel="stylesheet" href="../Stylesheet/tracking.css" />
  <script src="https://kit.fontawesome.com/503ea13a85.js" crossorigin="anonymous"></script>
</head>
<body>  <div class="sidebar">
    <a href="nurseDashboard.php"><i class="fa-solid fa-house fa-3x"></i></a>
    <a href="patientsList.php"><i class="fa-solid fa-hospital-user fa-3x"></i></a>
    <a href="tracking.php"><i class="fa-solid fa-clock fa-3x"></i></a>
    <a href="#"><i class="fa-solid fa-box fa-3x"></i></a>
  </div>

  <div class="main">
    <nav>
      <a href="nurseDashboard.php">Dashboard</a>
      <a href="#" class="active">Admission</a>
      <a href="tracking_log.php">Tracking Log</a>
      <a href="../Inventory/INVDASH.html">Inventory</a>
    </nav>
    <br>
    <div class="appointments-container">      
      <h2>Patient Tracking | <?php echo date('F d, Y'); ?></h2>
      <div class="search-container">
        <input type="text" id="searchInput" class="search-input" placeholder="Search by name...">
      </div>
      <table class="appointments-table">
        <thead>          <tr>
            <th>School No.</th>
            <th>Name</th>
            <th>Start Time</th>
            <th>End Time</th>
            <th>Status</th>
            <th>Tracking</th>
            <th>Last Seen in Clinic</th>
          </tr>
        </thead>
        <tbody>
          <?php
          try {            
            $query = "SELECT 
                        u.UID,
                        u.schoolID as school_no,
                        CONCAT(COALESCE(u.fname, ''), ' ', COALESCE(u.lname, '')) as name,
                        t.appID,
                        t.trackingStatusType as status,
                        t.trackingStart,
                        t.trackingEnd,
                        t.trackingStatus as tracking_status,
                        (
                            SELECT trackingEnd
                            FROM tracking t2 
                            WHERE t2.UID = u.UID 
                            AND t2.trackingEnd IS NOT NULL
                            AND t2.trackingID != COALESCE(t.trackingID, 0)
                            ORDER BY t2.trackingEnd DESC 
                            LIMIT 1
                        ) as last_seen
                      FROM userInfo u
                      LEFT JOIN tracking t ON u.UID = t.UID AND t.trackingStatus = 'Ongoing'
                      ORDER BY 
                        CASE WHEN t.trackingStatus = 'Ongoing' THEN 0 ELSE 1 END,
                        t.trackingStart DESC";

            $stmt = $conn->prepare($query);
            $stmt->execute();            if ($stmt->rowCount() > 0) {
              while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $isTracking = $row['tracking_status'] === 'Ongoing';
                
                echo "<tr>";                
                echo "<td>" . htmlspecialchars($row['school_no']) . "</td>";
                echo "<td>" . htmlspecialchars($row['name']) . "</td>";
                echo "<td>" . ($isTracking ? htmlspecialchars($row['trackingStart']) : '-') . "</td>";
                echo "<td>" . ($isTracking && !empty($row['trackingEnd']) ? htmlspecialchars($row['trackingEnd']) : '-') . "</td>";                
                echo "<td>" . (!empty($row['status']) ? htmlspecialchars($row['status']) : 'Not In Clinic') . "</td>";
                echo "<td>";
                
                if ($isTracking) {
                  echo "<button class='tracking-btn tracking-active'>Tracking...</button>";
                  echo "<button class='tracking-btn end-tracking' 
                          data-uid='" . $row['UID'] . "' 
                          data-appid='" . ($row['appID'] ?? 'null') . "'>
                          End Tracking
                        </button>";
                  if (!empty($row['trackingStart'])) {
                    echo "<br><span class='tracking-info' data-start='" . $row['trackingStart'] . "'>Started: " . $row['trackingStart'] . "</span>";
                  }
                } else {
                  echo "<button class='tracking-btn start-tracking' 
                          data-uid='" . $row['UID'] . "' 
                          data-appid='" . ($row['appID'] ?? 'null') . "'>
                          Start Tracking
                        </button>";
                }
                
                echo "</td>";
                $lastSeen = !empty($row['last_seen']) ? date('Y-m-d H:i:s', strtotime($row['last_seen'])) : '-';
                echo "<td>" . htmlspecialchars($lastSeen) . "</td>";
                echo "</tr>";
              }
            } else {
              echo "<tr><td colspan='8' style='text-align: center;'>No records found</td></tr>";
            }
          } catch (PDOException $e) {
            echo "<tr><td colspan='8' style='text-align: center; color: red;'>Error: " . $e->getMessage() . "</td></tr>";
          }
          ?>
        </tbody>
      </table>
    </div>
  </div>  
  <i class="fa-regular fa-user" id="profile"></i>  
  <script src="../JScripts/tracking.js"></script>
</body>
</html>
