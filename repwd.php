<?php
// 引入外部文件：test_input.php，一般用于过滤用户输入、防止XSS/恶意字符
require_once "test_input.php";

// 引入数据库连接文件：pdu_connect.php
// 这个文件里一定定义了 $pdo 变量（PDO数据库连接对象）
include "pdu_connect.php";

// -------------------------- 定义全局状态变量 --------------------------
// $error：存储【错误提示信息】，默认为空字符串
$error = "";

// $success：存储【成功提示信息】，默认为空字符串
$success = "";

// -------------------------- 判断请求方式：是否为POST提交 --------------------------
// $_SERVER["REQUEST_METHOD"] == "POST"
// 意思：只有当用户【点击表单提交按钮】时，才执行下面的密码重置逻辑
// 如果只是打开页面（GET方式），不执行任何PHP逻辑
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // -------------------------- 接收并处理表单提交的4个参数 --------------------------
    // 1. 接收用户名：isset()判断是否存在，存在就赋值，不存在赋值为空字符串
    $name = isset($_POST["name"]) ? $_POST["name"] : "";

    // 2. 接收邮箱 + 自动验证邮箱格式
    // filter_input：PHP内置安全函数，专门过滤/验证输入
    // FILTER_VALIDATE_EMAIL：邮箱格式验证，正确返回邮箱，错误返回false
    $email = filter_input(INPUT_POST, "email", FILTER_VALIDATE_EMAIL);

    // 3. 接收新密码
    $password = isset($_POST["password"]) ? $_POST["password"] : "";

    // 4. 接收确认密码
    $repwd = isset($_POST["repwd"]) ? $_POST["repwd"] : "";

    // -------------------------- 第一步验证：必填项不能为空 --------------------------
    // empty()：判断变量是否为空（空字符串、0、null、false 都算空）
    if (empty($name) || empty($email) || empty($password)) {
        // 任意一项为空，给错误信息
        $error = "用户名或密码邮箱不能为空";
        // goto END：直接跳转到代码最底部的 END: 标记，不再执行后面逻辑
        goto END;
    }

    // -------------------------- 第二步验证：两次密码必须一致 --------------------------
    if ($password != $repwd) {
        $error = "密码不一致请重新输入";
        goto END;
    }

    // -------------------------- 第三步验证：邮箱格式必须正确 --------------------------
    // 上面 filter_input 验证失败会返回 false
    if ($email === false) {
        $error = "邮箱格式不正确请重新输入";
        goto END;
    }

    // -------------------------- 第四步：查询数据库，验证用户名+邮箱是否存在 --------------------------
    // SQL语句：从 reg_user 表中查询 用户名=? 且 邮箱=? 的数据
    // :username 和 :email 是【PDO预处理占位符】，防SQL注入
    $sql = "SELECT * FROM reg_user WHERE email=:email AND username=:username";

    // $pdo->prepare()：PDO预处理SQL，防止SQL注入
    $stmt = $pdo->prepare($sql);

    // execute()：执行SQL，把真实数据传入占位符
    $stmt->execute([":username" => $name, ":email" => $email]);

    // $stmt->rowCount()：返回查询到的行数
    // 0 = 没找到这个用户 → 用户名/邮箱错误
    if ($stmt->rowCount() == 0) {
        $error = "用户名或邮箱不存在";
        goto END;
    }

    // -------------------------- 第五步：密码加密（非常重要！不能存明文） --------------------------
    // password_hash：PHP内置安全加密函数
    // PASSWORD_DEFAULT：自动使用当前最安全的加密算法（目前是 bcrypt）
    $hashed_pwd = password_hash($password, PASSWORD_DEFAULT);

    // -------------------------- 第六步：执行更新密码SQL --------------------------
    // 更新 reg_user 表，把 pwd 字段设置为加密后的新密码
    $update_sql = "UPDATE reg_user SET pwd=:pwd WHERE username=:username";

    // 预处理更新语句
    $update_stmt = $pdo->prepare($update_sql);

    // 执行更新，传入用户名和加密密码
    $result = $update_stmt->execute([":username" => $name, ":pwd" => $hashed_pwd]);

    // -------------------------- 第七步：判断更新是否成功 --------------------------
    if ($result) {
        // 执行成功 → 成功提示
        $success = "重置密码成功，即将跳转到登录页面";
        // header("refresh:2...")：2秒后自动跳转到 login.php
        header("refresh:2 url=login.php");
    } else {
        // 执行失败 → 错误提示
        $error = "重置失败请重试";
    }

    // -------------------------- goto 跳转的终点标记 --------------------------
    END:
}
?>

<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>重置密码</title>
    <style>
        :root {
            --macaron-pink: #f8c8dc;
            --macaron-blue: #b5d8f7;
            --macaron-purple: #d9c8f8;
            --macaron-green: #c6f0e4;
            --macaron-yellow: #ffe9a3;
            --soft-white: rgba(255, 255, 255, 0.85);
            --glass-bg: rgba(255, 255, 255, 0.55);
            --glass-border: rgba(255, 255, 255, 0.6);
            --shadow: 0 8px 30px rgba(0, 0, 0, 0.08);
            --backdrop: blur(20px);
            --radius: 20px;
            --transition: all 0.4s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: "Microsoft YaHei", "Segoe UI", Roboto, sans-serif;
        }

        body {
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            background: linear-gradient(-45deg, var(--macaron-pink), var(--macaron-blue), var(--macaron-purple), var(--macaron-green));
            background-size: 400% 400%;
            animation: gradientBg 12s ease infinite;
            position: relative;
            overflow: hidden;
        }

        @keyframes gradientBg {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .bg-decoration {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
            overflow: hidden;
        }

        .circle {
            position: absolute;
            border-radius: 50%;
            background: linear-gradient(135deg, rgba(255,255,255,0.3), rgba(255,255,255,0.1));
            backdrop-filter: blur(2px);
            animation: float 20s infinite ease-in-out;
        }

        .circle:nth-child(1) { width: 300px; height: 300px; top: -100px; left: -100px; animation-delay: 0s; }
        .circle:nth-child(2) { width: 200px; height: 200px; top: 50%; right: -50px; animation-delay: -5s; animation-duration: 25s; }
        .circle:nth-child(3) { width: 150px; height: 150px; bottom: 10%; left: 10%; animation-delay: -10s; animation-duration: 18s; }
        .circle:nth-child(4) { width: 250px; height: 250px; bottom: -80px; right: 20%; animation-delay: -15s; animation-duration: 22s; }
        .circle:nth-child(5) { width: 120px; height: 120px; top: 30%; left: 5%; animation-delay: -8s; animation-duration: 16s; }

        @keyframes float {
            0%, 100% { transform: translate(0, 0) rotate(0deg); }
            25% { transform: translate(30px, -30px) rotate(90deg); }
            50% { transform: translate(0, -50px) rotate(180deg); }
            75% { transform: translate(-30px, -30px) rotate(270deg); }
        }

        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
        }

        .particle {
            position: absolute;
            width: 8px;
            height: 8px;
            background: rgba(255, 255, 255, 0.6);
            border-radius: 50%;
            animation: rise 15s infinite ease-in;
        }

        .particle:nth-child(1) { left: 10%; animation-delay: 0s; animation-duration: 12s; }
        .particle:nth-child(2) { left: 20%; animation-delay: 2s; animation-duration: 14s; }
        .particle:nth-child(3) { left: 30%; animation-delay: 4s; animation-duration: 16s; }
        .particle:nth-child(4) { left: 40%; animation-delay: 1s; animation-duration: 13s; }
        .particle:nth-child(5) { left: 50%; animation-delay: 3s; animation-duration: 15s; }
        .particle:nth-child(6) { left: 60%; animation-delay: 5s; animation-duration: 11s; }
        .particle:nth-child(7) { left: 70%; animation-delay: 2.5s; animation-duration: 17s; }
        .particle:nth-child(8) { left: 80%; animation-delay: 1.5s; animation-duration: 14s; }
        .particle:nth-child(9) { left: 90%; animation-delay: 3.5s; animation-duration: 12s; }
        .particle:nth-child(10) { left: 15%; animation-delay: 4.5s; animation-duration: 18s; }

        @keyframes rise {
            0% { bottom: -10px; opacity: 0; transform: translateX(0) scale(0.5); }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { bottom: 110%; opacity: 0; transform: translateX(100px) scale(1); }
        }

        form {
            width: 100%;
            max-width: 440px;
            padding: 50px 42px;
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius);
            backdrop-filter: var(--backdrop);
            -webkit-backdrop-filter: var(--backdrop);
            box-shadow: var(--shadow);
            position: relative;
            z-index: 1;
            overflow: hidden;
            transition: var(--transition);
        }

        form::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(90deg, var(--macaron-pink), var(--macaron-blue), var(--macaron-purple), var(--macaron-green));
            background-size: 300% 100%;
            animation: flow 8s linear infinite;
        }

        form::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, var(--macaron-green), var(--macaron-yellow), var(--macaron-pink));
            background-size: 300% 100%;
            animation: flow 6s linear infinite reverse;
        }

        @keyframes flow {
            0% { background-position: 0% 50%; }
            100% { background-position: 300% 50%; }
        }

        form:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: 0 15px 35px rgba(0,0,0,0.12);
        }

        .logo-container {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo {
            width: 70px;
            height: 70px;
            background: linear-gradient(135deg, var(--macaron-pink), var(--macaron-purple));
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 20px rgba(248, 200, 220, 0.5);
            animation: logoFloat 3s ease-in-out infinite;
        }

        .logo svg {
            width: 35px;
            height: 35px;
            fill: #fff;
        }

        @keyframes logoFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-8px); }
        }

        .form-title {
            text-align: center;
            font-size: 28px;
            font-weight: 700;
            color: #666;
            margin-bottom: 35px;
            letter-spacing: 1.5px;
            position: relative;
        }

        .form-title::after {
            content: '';
            display: block;
            width: 60px;
            height: 3px;
            background: linear-gradient(90deg, var(--macaron-pink), var(--macaron-purple));
            margin: 15px auto 0;
            border-radius: 2px;
        }

        .error {
            background: rgba(255, 186, 186, 0.5);
            color: #d16969;
            padding: 13px 16px;
            border-radius: 12px;
            text-align: center;
            margin-bottom: 24px;
            font-weight: 500;
            backdrop-filter: blur(6px);
            border: 1px solid rgba(255,255,255,0.6);
            animation: shake 0.4s ease;
        }

        .success {
            background: rgba(198, 240, 228, 0.5);
            color: #5a9b8a;
            padding: 13px 16px;
            border-radius: 12px;
            text-align: center;
            margin-bottom: 24px;
            font-weight: 500;
            backdrop-filter: blur(6px);
            border: 1px solid rgba(255,255,255,0.6);
        }

        @keyframes shake {
            0%,100%{transform:translateX(0);}
            25%{transform:translateX(-6px);}
            75%{transform:translateX(6px);}
        }

        .input-group {
            position: relative;
            margin-bottom: 24px;
        }

        .input-icon {
            position: absolute;
            left: 18px;
            top: 65%;
            transform: translateY(-50%);
            width: 20px;
            height: 20px;
            fill: #aaa;
            transition: var(--transition);
            z-index: 2;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .input-group label {
            display: block;
            color: #777;
            font-weight: 600;
            font-size: 15px;
            margin-bottom: 10px;
        }

        .input-group input[type="text"],
        .input-group input[type="password"],
        .input-group input[type="email"] {
            width: 100%;
            padding: 15px 18px 15px 48px;
            margin-bottom: 0;
            background: var(--soft-white);
            border: 2px solid rgba(180, 180, 180, 0.2);
            border-radius: 14px;
            color: #666;
            font-size: 16px;
            transition: var(--transition);
            outline: none;
        }

        .input-group input:focus {
            border-color: var(--macaron-purple);
            box-shadow: 0 0 0 4px rgba(217, 200, 248, 0.4), 0 0 20px rgba(217, 200, 248, 0.3);
            transform: scale(1.02);
        }

        .input-group input:focus ~ .input-icon,
        .input-group:hover .input-icon {
            fill: var(--macaron-purple);
            transform: translateY(-50%) scale(1.1);
        }

        .input-group input::placeholder {
            color: #aaa;
        }

        .btn-group {
            display: flex;
            flex-direction: column;
            gap: 14px;
            margin-top: 10px;
        }

        button {
            width: 100%;
            padding: 16px;
            border: none;
            border-radius: 14px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            letter-spacing: 0.8px;
            color: #fff;
            position: relative;
            overflow: hidden;
        }

        button::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: 0.5s;
        }

        button:hover::before {
            left: 100%;
        }

        button[type="submit"] {
            background: linear-gradient(135deg, var(--macaron-pink), var(--macaron-purple));
            box-shadow: 0 4px 15px rgba(248, 200, 220, 0.4);
        }

        button[type="button"] {
            background: linear-gradient(135deg, var(--macaron-blue), var(--macaron-green));
            box-shadow: 0 4px 15px rgba(181, 216, 247, 0.4);
        }

        button:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            filter: brightness(1.08);
        }

        button:active {
            transform: translateY(0);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .footer-links {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(180, 180, 180, 0.2);
        }

        .footer-links a {
            color: #888;
            text-decoration: none;
            font-size: 14px;
            transition: var(--transition);
        }

        .footer-links a:hover {
            color: var(--macaron-purple);
        }

        @media (max-width: 480px) {
            form { padding: 40px 28px; }
            .form-title { font-size: 24px; }
            .circle:nth-child(1) { width: 200px; height: 200px; }
            .circle:nth-child(2) { width: 150px; height: 150px; }
            .circle:nth-child(3) { width: 100px; height: 100px; }
            .circle:nth-child(4) { width: 180px; height: 180px; }
            .circle:nth-child(5) { width: 80px; height: 80px; }
        }
    </style>
</head>
<body>
<div class="bg-decoration">
    <div class="circle"></div>
    <div class="circle"></div>
    <div class="circle"></div>
    <div class="circle"></div>
    <div class="circle"></div>
</div>
<div class="particles">
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
</div>
<form method="post" action="" onsubmit="return confirm('确定要修改密码吗？');">
    <div class="logo-container">
        <div class="logo">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
            </svg>
        </div>
    </div>
    <h2 class="form-title">重置密码</h2>

    <?php if($error):?>
        <p class="error"><?PHP echo $error ?></p>
    <?php endif;?>

    <?php if($success):?>
        <p class="success"><?PHP echo $success ?></p>
    <?php endif;?>

    <div class="input-group">
        <label for="name">用户名</label>
        <svg class="input-icon" viewBox="0 0 24 24">
            <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
        </svg>
        <input id="name" type="text" name="name" placeholder="请输入用户名">
    </div>

    <div class="input-group">
        <label for="email">邮箱</label>
        <svg class="input-icon" viewBox="0 0 24 24">
            <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/>
        </svg>
        <input id="email" type="email" name="email" placeholder="请输入邮箱">
    </div>

    <div class="input-group">
        <label for="password">新密码</label>
        <svg class="input-icon" viewBox="0 0 24 24">
            <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
        </svg>
        <input id="password" type="password" name="password" placeholder="请输入新密码">
    </div>

    <div class="input-group">
        <label for="repwd">确认密码</label>
        <svg class="input-icon" viewBox="0 0 24 24">
            <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
        </svg>
        <input id="repwd" type="password" name="repwd" placeholder="请再次输入密码">
    </div>

    <div class="btn-group">
        <button type="submit">重置密码</button>
        <button type="button" onclick="window.location.href='login.php'">返回登录</button>
    </div>

    <div class="footer-links">
        <a href="login.php">返回登录页面</a>
    </div>
</form>
</body>
</html>