<?php
# Incluir conexão
require_once "conexao/conecta.php";


#
# Definir variáveis e inicializá-las com valores vazios
$username_err = $email_err = $password_err = $nationality_err = $province_err = $occupation_err = "";
$username = $email = $password = $nationality = $province = $occupation = "";

# Processar dados do formulário quando submetidos
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  # Validar usuário
  if (empty(trim($_POST["username"]))) {
    $username_err = "Por favor, insira um nome de usuário.";
  } else {
    $username = trim($_POST["username"]);
    if (!ctype_alnum(str_replace(array("@", "-", "_"), "", $username))) {
      $username_err = "O nome de usuário só pode conter letras, números e símbolos como '@', '_', ou '-'.";
    } else {
      # Preparar um comando select
      $sql = "SELECT id FROM users WHERE username = ?";

      if ($stmt = mysqli_prepare($db, $sql)) {
        # Vincular variáveis ao comando como parâmetros
        mysqli_stmt_bind_param($stmt, "s", $param_username);

        # Definir parâmetros
        $param_username = $username;

        # Executar o comando preparado
        if (mysqli_stmt_execute($stmt)) {
          # Armazenar resultado
          mysqli_stmt_store_result($stmt);

          # Verificar se o nome de usuário já está registrado
          if (mysqli_stmt_num_rows($stmt) == 1) {
            $username_err = "Este nome de usuário já está registrado.";
          }
        } else {
          echo "<script>" . "alert('Ops! Algo deu errado. Por favor, tente novamente mais tarde.')" . "</script>";
        }

        # Fechar comando
        mysqli_stmt_close($stmt);
      }
    }
  }

  # Validar email
  if (empty(trim($_POST["email"]))) {
    $email_err = "Por favor, insira um endereço de email";
  } else {
    $email = filter_var($_POST["email"], FILTER_SANITIZE_EMAIL);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $email_err = "Por favor, insira um endereço de email válido.";
    } else {
      # Preparar um comando select
      $sql = "SELECT id FROM users WHERE email = ?";

      if ($stmt = mysqli_prepare($db, $sql)) {
        # Vincular variáveis ao comando como parâmetros
        mysqli_stmt_bind_param($stmt, "s", $param_email);

        # Definir parâmetros
        $param_email = $email;

        # Executar o comando preparado
        if (mysqli_stmt_execute($stmt)) {
          # Armazenar resultado
          mysqli_stmt_store_result($stmt);

          # Verificar se o email já está registrado
          if (mysqli_stmt_num_rows($stmt) == 1) {
            $email_err = "Este email já está registrado.";
          }
        } else {
          echo "<script>" . "alert('Ops! Algo deu errado. Por favor, tente novamente mais tarde.');" . "</script>";
        }

        # Fechar comando
        mysqli_stmt_close($stmt);
      }
    }
  }

  # Validar senha
  if (empty(trim($_POST["password"]))) {
    $password_err = "Por favor, insira uma senha.";
  } else {
    $password = trim($_POST["password"]);
    if (strlen($password) < 8) {
      $password_err = "A senha deve conter pelo menos 8 caracteres ou mais.";
    }
  }

  
  
  
# Validar nacionalidade
if (empty(trim($_POST["nationality"]))) {
    $nationality_err = "Por favor, insira sua nacionalidade.";
} else {
    $nationality = trim($_POST["nationality"]);
    // Converte a nacionalidade para minúsculas e remove espaços extras
    $normalized_nationality = strtolower(trim($nationality));
    if ($normalized_nationality !== "moçambicano") {
        $nationality_err = "Desculpe, o registro está disponível apenas para moçambicanos.";
    }
}

# Exibir a mensagem de erro se necessário
if (!empty($nationality_err)) {
    echo "<div class='alert alert-danger' role='alert'>" . $nationality_err . "</div>";
}




  else {
    $nationality = trim($_POST["nationality"]);
  }

  # Validar província
  if (empty(trim($_POST["province"]))) {
    $province_err = "Por favor, insira sua província.";
  } else {
    $province = trim($_POST["province"]);
  }

  # Validar ocupação
  if (empty(trim($_POST["occupation"]))) {
    $occupation_err = "Por favor, insira sua ocupação.";
  } else {
    $occupation = trim($_POST["occupation"]);
  }

  # Verificar erros de entrada antes de inserir dados no banco de dados
  if (empty($username_err) && empty($email_err) && empty($password_err) && empty($nationality_err) && empty($province_err) && empty($occupation_err)) {
    # Preparar um comando insert
    $sql = "INSERT INTO users(username, email, password, nationality, province, occupation) VALUES (?, ?, ?, ?, ?, ?)";

    if ($stmt = mysqli_prepare($db, $sql)) {
      # Vincular variáveis ao comando preparado como parâmetros
      mysqli_stmt_bind_param($stmt, "ssssss", $param_username, $param_email, $param_password, $param_nationality, $param_province, $param_occupation);

      # Definir parâmetros
      $param_username = $username;
      $param_email = $email;
      $param_password = password_hash($password, PASSWORD_DEFAULT);
      $param_nationality = $nationality;
      $param_province = $province;
      $param_occupation = $occupation;

      # Executar o comando preparado
      if (mysqli_stmt_execute($stmt)) {
        echo "<script>" . "alert('Registro completado com sucesso. Faça login para continuar.');" . "</script>";
        echo "<script>" . "window.location.href='./login.php';" . "</script>";
        exit;
      } else {
        echo "<script>" . "alert('Ops! Algo deu errado. Por favor, tente novamente mais tarde.');" . "</script>";
      }

      # Fechar comando
      mysqli_stmt_close($stmt);
    }
  }

  # Fechar conexão
  mysqli_close($db);
}
?>

</head>
<body class="home-welcome-text" style=" background-image: url('img/y.jpg');background-size: cover;background-position: center;">


<!-- estilos -->

<link rel="stylesheet" href="ESTILOSstyle.css">
<link rel="stylesheet" href="ESTILOS/main.css">


<!-- fim de estilos -->

  <div class="container">
    <div class="row min-vh-100 justify-content-center align-items-center">
      <div class="col-lg-5">
<div class="form-wrap border rounded p-4">
  <h1>Cadastre-se Na LIVRARIA BOOKATOES</h1>
  <p>Por favor, preencha este formulário para se registrar</p>

          <!-- form starts here -->
          <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"




<form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="mb-3">
              <label for="username" class="form-label">Usuário</label>
              <input type="text" class="form-control" name="username" id="username" value="<?= $username; ?>">
              <small class="text-danger"><?= $username_err; ?></small>
              
              
                          
            <div class="mb-3">
              <label for="nationality" class="form-label">Nacionalidade</label>
              <input type="text" class="form-control" name="nationality" id="nationality" value="<?= $nationality; ?>">
              <small class="text-danger"><?= $nationality_err; ?></small>
            </div>
            
            
            <div class="mb-3">
              <label for="province" class="form-label">Província</label>
              <input type="text" class="form-control" name="province" id="province" value="<?= $province; ?>">
              <small class="text-danger"><?= $province_err; ?></small>
            </div>
            
            
            <div class="mb-3">
              <label for="occupation" class="form-label">Ocupação</label>
              <input type="text" class="form-control" name="occupation" id="occupation" value="<?= $occupation; ?>">
              <small class="text-danger"><?= $occupation_err; ?></small>
            </div>
            
              
              
              
              
            </div>
            <div class="mb-3">
              <label for="email" class="form-label">Endereço de Email</label>
              <input type="email" class="form-control" name="email" id="email" value="<?= $email; ?>">
              <small class="text-danger"><?= $email_err; ?></small>
            </div>
            
            
            <div class="mb-2">
              <label for="password" class="form-label">Senha</label>
              <input type="password" class="form-control" name="password" id="password" value="<?= $password; ?>">
              <small class="text-danger"><?= $password_err; ?></small>
            </div>
            

            
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="togglePassword">
              <label class="form-check-label" for="togglePassword">Mostrar Senha</label>
            </div>
            <div class="mb-3">
              <input type="submit" class="btn btn-primary form-control" name="submit" value="Cadastrar">
            </div>
            <p class="mb-0">Já tem uma conta? <a href="./login.php">Entrar</a></p>
          </form>
          <!-- form ends here -->
        </div>
      </div>
    </div>
  </div>

  <script>
    document.getElementById('togglePassword').addEventListener('click', function (e) {
      const passwordInput = document.getElementById('password');
      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
      } else {
        passwordInput.type = 'password';
      }
    });
  </script>
  <!-- script -->
  <script src="SCRIPTS/bootstrap.min.js"></script>
<script src="SCRIPTS/jquery.min.js"></script>

</body>
</html>