<?php
    //echo $_POST['username'];
    //echo $_REQUEST['username'];
    //echo 'Привет, ' . htmlspecialchars($_GET["username"]) . '!<br>';	
    //echo $_POST['operation'];

    class Calculator
    {
        public $num1;
        public $num2;
        public static bool $instance = false;

        protected function __construct($a, $b) {
            $this->num1 = $a;
            $this->num2 = $b;
        }

        public static function getInstance($a, $b) {
            if (Calculator::$instance == false) {
                Calculator::$instance = true;
                return new Calculator($a, $b);
            }

            throw new Exception("It is a singleton pattern!");
        }

        public function Result($op) {
            switch($op) {
                case 1:                
                    return "Сложение: ".$this->Sum($this->num1, $this->num2);
                    break;
                case 2:
                    return "Вычитание: " . $this->Min($this->num1, $this->num2);
                    break;
                case 3:
                    return "Умножение: " . $this->Multiply($this->num1, $this->num2);
                    break;
                case 4:
                    return "Деление: " . $this->Divide($this->num1, $this->num2);
                    break;
                case 5:
                    return "Корень 1: " . $this->Root($this->num1, $this->num2);
                    break;
            }
        }

        public function Sum($num1, $num2) {
            return $num1 + $num2;
        }

        public function Min($num1, $num2) {
            return $num1 - $num2;
        }

        public function Multiply($num1, $num2) {
            return $num1 * $num2;
        }

        public function Divide($num1, $num2) {
            return $num1 / $num2;
        }

        public function Root($num1, $num2) {
            return strval($num1 ** 0.5) . "<br>Корень 2: " . strval($num2 ** 0.5);
        }
    }  

    $num_1 = $_POST['num1'];
    $num_2 = $_POST['num2'];

    $op_index = $_POST['operation'];
    $calc = Calculator::getInstance($num_1, $num_2);

    function main() {
        global $calc;
        global $op_index;
        echo $calc->Result($op_index);
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My calculator</title>
    <link href="css/style.css" rel="stylesheet">
</head>
<body>    
    <div class="box">
        <div style="font-size: 30px;">
            <?
                main(); 
            ?>
        </div>

        <input class="glow-button" type="submit" name="submit" value="Вернуться назад" onclick="history.back();"/>

    </div>
</body>
</html>