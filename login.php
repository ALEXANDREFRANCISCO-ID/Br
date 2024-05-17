<?php
require_once "conexao/conecta.php";
# Initialize session
session_start();

# Check if user is already logged in, If yes then redirect him to index page
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] == TRUE) {
    echo "<script>" . "window.location.href='./'" . "</script>";
    exit;
}

    # Define variables and initialize with empty values
    $user_login_err = $user_password_err = $login_err = "";
    $user_login = $user_password = "";

    # Processing form data when form is submitted
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
          if (empty(trim($_POST["user_login"]))) {
            $user_login_err = "Please enter your username or an email id.";
      } else {
             $user_login = trim($_POST["user_login"]);
      }

        if (empty(trim($_POST["user_password"]))) {
          $user_password_err = "Please enter your password.";
        } else {
          $user_password = trim($_POST["user_password"]);
        }

  # Validate credentials 
  if (empty($user_login_err) && empty($user_password_err)) {
    # Prepare a select statement
    $sql = "SELECT id, username, password FROM users WHERE username = ? OR email = ?";

    if ($stmt = mysqli_prepare($db, $sql)) {
      # Bind variables to the statement as parameters
      mysqli_stmt_bind_param($stmt, "ss", $param_user_login, $param_user_login);

      # Set parameters
      $param_user_login = $user_login;

      # Execute the statement
      if (mysqli_stmt_execute($stmt)) {
        # Store result
        mysqli_stmt_store_result($stmt);

        # Check if user exists, If yes then verify password
        if (mysqli_stmt_num_rows($stmt) == 1) {
          # Bind values in result to variables
          mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);

          if (mysqli_stmt_fetch($stmt)) {
            # Check if password is correct
            if (password_verify($user_password, $hashed_password)) {

              # Store data in session variables
              $_SESSION["id"] = $id;
              $_SESSION["username"] = $username;
              $_SESSION["loggedin"] = TRUE;

              # Redirect user to index page
              echo "<script>" . "window.location.href='./'" . "</script>";
              exit;
            } else {
              # If password is incorrect show an error message
              $login_err = "The email or password you entered is incorrect.";
            }
          }
        } else {
          # If user doesn't exists show an error message
          $login_err = "Email ou senha invalida.";
        }
      } else {
        echo "<script>" . "alert('Oops! Something went wrong. Please try again later.');" . "</script>";
        echo "<script>" . "window.location.href='./login.php'" . "</script>";
        exit;
      }

      # Close statement
      mysqli_stmt_close($stmt);
    }
  }

  # Close connection
  mysqli_close($db);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
 





  <script defer src="./js/script.js"></script>
</head>
<body class="home-welcome-text" style="background-image: url(img/login.jpg);background-size:cover; height:100%; "> 


<!-- estilos -->

<link rel="stylesheet" href="ESTILOSstyle.css">
<link rel="stylesheet" href="ESTILOS/main.css">


<!-- fim de estilos -->




<div class="container">
    <div class="row min-vh-100 justify-content-center align-items-center">
      <div class="col-lg-5">
        <?php
        if (!empty($login_err)) {
          echo "<div class='alert alert-danger'>" . $login_err . "</div>";
        }
        ?>
        <div class="form-wrap border rounded p-4">
          <h1>Entrar</h1>
          <p>Por favor entre para continuar </p>
          <!-- form starts here -->
          <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" novalidate>
            <div class="mb-3">
              <label for="user_login" class="form-label">Nome do Usuario ou email</label>
              <input type="text" class="form-control" name="user_login" id="user_login" value="<?= $user_login; ?>">
              <small class="text-danger"><?= $user_login_err; ?></small>
            </div>
            <div class="mb-2">
              <label for="password" class="form-label">Senha</label>
              <input type="password" class="form-control" name="user_password" id="password">
              <small class="text-danger"><?= $user_password_err; ?></small>
            </div>
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="togglePassword">
              <label for="togglePassword" class="form-check-label">Mostrar Senha </label>
            </div>
            <div class="mb-3">
              <input type="submit" class="btn btn-primary form-control" name="submit" value="Entrar">
            </div>
            <p class="mb-0">Não tem conta? <a href="./register.php">Regista-Se</a></p>
          </form>
          <!-- form ends here -->
        </div>
      </div>
    </div>
  </div>
  <!-- script -->
  <script src="SCRIPTS/bootstrap.min.js"></script>
<script src="SCRIPTS/jquery.min.js"></script>

</body>

</html>