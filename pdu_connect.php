<?php
$host = "localhost";
$dbname = "school";//连接数据库的名称：db为数据库
$username = "root";
$password = "root";
$charset = "utf8mb4";//字符集

$dsn = "mysql:host=$host;dbname=$dbname;charset=$charset";//数据源名称：数据库类型、主机名、连接数据库名、字符集

$options =[
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,//抛出异常
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,//警告异常后，以关联数组形式返回
    PDO::ATTR_EMULATE_PREPARES => false,//禁止模拟预处理
];//错误提示---抛出异常

try{//尝试连接
    $pdo = new PDO($dsn, $username, $password, $options);//连接信息

}catch (PDOException $e){
    die("数据库连接失败".$e->getMessage());//数据库连接失败并返回具体报错信息
}
