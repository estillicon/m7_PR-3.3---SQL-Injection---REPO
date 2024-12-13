<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL injection</title>
    <style>
        /*un minimo de estilos*/
        body {
            display: flex;
            flex-direction: column;
            align-items: center;
            background-color: lightblue;
        }

        .user {
            background-color: red;
            color: white;
        }
    </style>
</head>

<body>
    <h1>PDO vulnerable a SQL injection</h1>

    <?php
    // sql injection possible:
    
    if (isset($_POST["nombre"]) && isset($_POST["pass"])) {

        $user = $_POST["nombre"];
        $pass = $_POST["pass"];

        // Depuración: Imprimir los valores recibidos
        //echo "<br>Usuario: $user, Contraseña: $pass<br>";

        // Validar si el campo de contraseña está vacío
        if (empty($user) || empty($pass)) {
            echo "<div class='user'>Por favor ingresa tanto el usuario como la contraseña.</div>";
            exit;
        }
        # Conectar a la base de datos con control de errores
        try {
            $hostname = "localhost";
            $dbname = "users";
            $username = "admin";
            $pw = "admin";
            $pdo = new PDO("mysql:host=$hostname;dbname=$dbname", "$username", "$pw");
        } catch (PDOException $e) {
            echo "Failed to get DB handle: " . $e->getMessage() . "\n";
            exit;
        }

        # Preparar la consulta
        $query = "SELECT * FROM user WHERE nombre = :nombre AND pass = SHA2(:pass, 256)";

        # Prepara la consulta
        $consulta = $pdo->prepare($query);

        # Depuración: Mostrar la consulta preparada
        //echo "<br>Consulta preparada: $query<br>";

        # Vincula los valores de las variables utilizando bindValue
        $consulta->bindValue(":nombre", $user, PDO::PARAM_STR);
        $consulta->bindValue(":pass", $pass, PDO::PARAM_STR);

        # Ejecuta la consulta
        $consulta->execute();

        # Verificar si hubo errores en la ejecución
        $error = $consulta->errorInfo();
        if ($error[0] != '00000') {
            echo "<div class='user'>Error en la consulta: " . $error[2] . "</div>";
            die();
        }

        # Verificación de resultados
        if ($consulta->rowCount() > 0) {
            foreach ($consulta as $user) {
                echo "<div class='user'>Hola " . htmlspecialchars($user["nombre"]) . "</div>";
            }
        } else {
            echo "<div class='user'>No hay usuarios con ese nombre y contraseña.</div>";
        }
    } else {
        echo "<div class='user'>No has iniciado sesión</div>";
    }
    ?>
    <!--formulario -->
    <fieldset>
        <legend>Login form</legend>
        <form method="post">
            User: <input type="text" name="nombre" required /><br>
            Pass: <input type="password" name="pass" required/><br>
            <input type="submit" value="Login" /><br>
        </form>
    </fieldset>

</body>

</html>
