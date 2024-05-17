<script>
if (window.location.protocol != "https:") {
    window.location.href = "https:" + window.location.href.substring(window.location.protocol.length);
}
</script>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <style>
        .call-button {
            display: inline-block;
            padding: 10px;
            background-color: #007bff;
            color: #fff;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
        .call-button:hover {
            background-color: #0056b3;
        }
    </style>
    <title>Call Button</title>
</head>
<body>

<a href="tel:+1234567890" class="call-button">
    <i class="material-icons">phone</i> Ligar
</a>

</body>
</html>