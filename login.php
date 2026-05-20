<?php
// 1. 启动PHP会话机制，必须放在最顶部，用于存储登录状态（如用户名、角色）
session_start();

// 2. 引入自定义函数文件：test_input.php（一般用于过滤用户输入、防XSS/特殊字符）
require_once "test_input.php";

// 3. 引入数据库连接文件：pdu_connect.php（里面包含PDO数据库连接对象$pdo）
include 'pdu_connect.php';

// 4. 定义错误提示变量，初始为空，登录出错时赋值提示文字
$error = "";

// 5. 判断浏览器是否存在【记住用户名】的Cookie
// 如果有，把Cookie里的用户名赋值给$default_name，用于表单自动填充
if(isset($_COOKIE['remember_me'])){
    $default_name = $_COOKIE['remember_me'];
}else{
    // 没有Cookie则默认空字符串
    $default_name='';
}

// 6. 判断当前请求方式是否为【POST】（只有用户点击登录按钮提交表单才会进入）
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // 7. 接收表单提交的【用户名】，存在则赋值，不存在则为空
    $name=isset($_POST["name"])?$_POST["name"]:"";

    // 8. 接收表单提交的【密码】
    $password = isset($_POST["password"])?$_POST["password"]:"";

    // 9. 接收【记住用户名】勾选状态，勾选=true，未勾选=false
    $remember = isset($_POST["remember"])? true:false;

    // 10. 前端校验：用户名为空，赋值错误信息，跳转到END结束登录验证
    if(empty($name) ){
        $error ="用户名不能为空";
        goto END;
    }

    // 11. 前端校验：密码为空，赋值错误信息，跳转到END
    if(empty($password) ){
        $error="密码不能为空";
        goto END;
    }

    // ===================== 数据库验证开始 =====================
    // 12. SQL查询语句：从reg_user表中查询【用户名匹配】的用户数据
    // :username 是PDO预处理占位符，防SQL注入
    $sql = "SELECT * FROM reg_user WHERE username=:username";

    // 13. 预处理SQL语句，返回PDOStatement对象$stmt
    $stmt = $pdo->prepare($sql);

    // 14. 执行SQL，把用户名绑定到占位符:username
    $stmt->execute([':username'=>$name]);

    // 15. 判断查询结果行数：0=用户不存在
    if($stmt->rowCount()==0){
        $error="用户不存在，请注册！";
        goto END;
    }

    // 16. 获取查询到的用户数据（一维数组）
    $row = $stmt->fetch();

    // 17. 从数据库中取出【加密后的密码】
    $hashed_password=$row['pwd'];

    // 18. 密码验证：用户输入的明文密码 VS 数据库加密密码
    // password_verify()是PHP内置函数，专门验证password_hash加密的密码
    $result = password_verify($password,$hashed_password);

    // 19. 验证失败=密码错误
    if(!$result){
        $error="密码错误，请重新输入！";
        goto END;
    }
    // ===================== 数据库验证结束 =====================

    // 20. 从用户数据中取出【角色标识】：1=管理员，其他=普通用户
    $user_role=$row['role'];

    // 21. 把【用户名】存入SESSION，标志用户已登录
    $_SESSION['username']=$row['username'];

    // 22. 把【角色】存入SESSION，用于页面权限判断
    $_SESSION['role']=$row['role'];

    // 23. 处理【记住用户名】Cookie
    if($remember){
        // 勾选：创建Cookie，有效期7天，全站有效
        setcookie("remember_me",$name,time() +7*24*60*60,"/");
    }else{
        // 未勾选：删除Cookie（设置过期时间为过去）
        setcookie("remember_me","",time() -3600,"/");
    }

    // 24. 根据角色跳转到不同欢迎页
    if($user_role=='1'){
        // 角色=1 → 管理员登录
        $_SESSION['admin_login']=true;
        echo "<script>alert('登陆成功!\\n 欢迎管理员:" . $row['username'] . "');location.href='welcome.php';</script>";
    }else{
        // 普通用户登录
        echo "<script>alert('登陆成功\\n 欢迎你:".$row['username']."');location.href='welcome.php';</script>";
    }

    // 25. goto跳转标记：校验失败时直接跳到这里，不再执行后续登录逻辑
    END:
}

?>
<!DOCTYPE html>
<html lang="zh_cn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
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

        .circle:nth-child(1) {
            width: 300px;
            height: 300px;
            top: -100px;
            left: -100px;
            animation-delay: 0s;
        }

        .circle:nth-child(2) {
            width: 200px;
            height: 200px;
            top: 50%;
            right: -50px;
            animation-delay: -5s;
            animation-duration: 25s;
        }

        .circle:nth-child(3) {
            width: 150px;
            height: 150px;
            bottom: 10%;
            left: 10%;
            animation-delay: -10s;
            animation-duration: 18s;
        }

        .circle:nth-child(4) {
            width: 250px;
            height: 250px;
            bottom: -80px;
            right: 20%;
            animation-delay: -15s;
            animation-duration: 22s;
        }

        .circle:nth-child(5) {
            width: 120px;
            height: 120px;
            top: 30%;
            left: 5%;
            animation-delay: -8s;
            animation-duration: 16s;
        }

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
            animation: shake 0.4s ease, errorPulse 2s ease-in-out infinite;
        }

        @keyframes shake {
            0%,100%{transform:translateX(0);}
            25%{transform:translateX(-6px);}
            75%{transform:translateX(6px);}
        }

        @keyframes errorPulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(209, 105, 105, 0.3); }
            50% { box-shadow: 0 0 15px 5px rgba(209, 105, 105, 0.2); }
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
        .input-group input[type="password"] {
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

        .input-group input[type="text"]:focus,
        .input-group input[type="password"]:focus {
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

        .checkbox-wrap {
            display: flex;
            align-items: center;
            color: #777;
            font-size: 15px;
            margin-bottom: 30px;
            cursor: pointer;
            transition: var(--transition);
        }

        .checkbox-wrap:hover {
            color: var(--macaron-purple);
        }

        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            margin-right: 10px;
            accent-color: var(--macaron-purple);
            cursor: pointer;
        }

        .btn-group {
            display: flex;
            flex-direction: column;
            gap: 14px;
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

        .btn-loading {
            pointer-events: none;
        }

        .btn-loading::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            top: 50%;
            left: 50%;
            margin-left: -10px;
            margin-top: -10px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
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
            margin: 0 10px;
        }

        .footer-links a:hover {
            color: var(--macaron-purple);
        }

        .footer-links span {
            color: #ccc;
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

        @media (max-width: 480px) {
            form {
                padding: 40px 28px;
            }
            .form-title {
                font-size: 24px;
            }
            .circle:nth-child(1) { width: 200px; height: 200px; }
            .circle:nth-child(2) { width: 150px; height: 150px; }
            .circle:nth-child(3) { width: 100px; height: 100px; }
            .circle:nth-child(4) { width: 180px; height: 180px; }
            .circle:nth-child(5) { width: 80px; height: 80px; }
        }

        @media (max-width: 360px) {
            form {
                padding: 30px 20px;
            }
            .form-title {
                font-size: 22px;
            }
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
<form method="post" action="" id="loginForm">
    <div class="logo-container">
        <div class="logo">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
            </svg>
        </div>
    </div>
    <h2 class="form-title">账户登录</h2>

    <?php if ($error):?>
        <p class="error"><?php echo $error;?></p>
    <?php endif;?>

    <div class="input-group">
        <label for="name">用户名</label>
        <svg class="input-icon" viewBox="0 0 24 24">
            <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
        </svg>
        <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($default_name);?>" placeholder="请输入用户名">
    </div>

    <div class="input-group">
        <label for="password">密码</label>
        <svg class="input-icon" viewBox="0 0 24 24">
            <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
        </svg>
        <input type="password" id="password" name="password" placeholder="请输入密码">
    </div>

    <div class="checkbox-wrap">
        <input type="checkbox" name="remember" id="remember" <?php echo $default_name ? 'checked' : '' ?>>
        <label for="remember" style="margin-bottom: 0; cursor: pointer;">记住用户名</label>
    </div>

    <div class="btn-group">
        <button type="submit" id="loginBtn">登录</button>
        <button type="button" onclick="window.location.href='reuser.php'">注册账号</button>
        <button type="button" onclick="window.location.href='repwd.php'" style="background: linear-gradient(135deg, var(--macaron-yellow), #f0d78c); box-shadow: 0 4px 15px rgba(255, 233, 163, 0.4);">忘记密码</button>
    </div>

    <div class="footer-links">
        <a href="welcome.php">返回首页</a>
    </div>
</form>
<script>
    document.getElementById('loginForm').addEventListener('submit', function(e) {
        const btn = document.getElementById('loginBtn');
        btn.classList.add('btn-loading');
        btn.textContent = '';
    });
</script>
</body>
</html>