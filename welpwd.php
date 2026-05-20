<?php
// 开启会话功能，必须放在所有输出之前，用于读取/存储用户登录状态
// 作用：让服务器知道当前是哪个用户在访问，读取登录信息
session_start();

// 引入自定义的输入过滤函数文件
// 作用：test_input() 函数一般用来过滤用户输入的特殊字符、防XSS攻击
require_once "test_input.php";

// 引入数据库连接文件
// 作用：这个文件里一般定义了 $pdo 变量，是PHP操作MySQL的数据库连接对象
include "pdu_connect.php";

// 判断用户是否登录：检查会话里是否存在 username，并且不为空
// !isset($_SESSION['username'])：会话中没有存储用户名
// empty($_SESSION['username'])：会话中的用户名是空值
if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
    // 未登录 → 跳转到登录页面
    header("Location: login.php");
    // 跳转后立即终止脚本执行，防止后面代码继续运行
    exit;
}

// 已登录，获取当前登录的用户名
// test_input()：过滤用户名，防止恶意输入、安全处理
$username = test_input($_SESSION['username']);

// 定义提示信息变量
// 作用：存储错误/成功提示文字，默认空字符串
$msg = "";

// 判断当前请求方式是否为 POST
// 只有用户点击【提交修改】按钮，表单才会用 POST 方式提交
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 获取用户在表单中输入的 原密码，trim() 去除首尾空格
    $oldpwd = trim($_POST['oldpwd']);
    // 获取用户输入的 新密码
    $newpwd = trim($_POST['newpwd']);
    // 获取用户输入的 确认新密码
    $newpwd2 = trim($_POST['newpwd2']);

    // 验证1：两次输入的新密码必须一致
    if ($newpwd !== $newpwd2) {
        // 不一致 → 给提示信息赋值
        $msg = "两次新密码输入不一致！";
        // 跳转到 END 标记处，结束本次密码修改逻辑
        goto END;
    }

    // 验证2：新密码不能为空
    if (empty($newpwd)) {
        $msg = "新密码不能为空！";
        goto END;
    }

    // try 包裹数据库操作，防止数据库报错导致程序崩溃
    try {
        // 准备SQL语句：根据用户名查询数据库中存储的密码
        // ? 是PDO预处理占位符，防SQL注入攻击
        $stmt = $pdo->prepare("SELECT `pwd` FROM `reg_user` WHERE `username` = ?");

        // 执行SQL语句，把用户名传入占位符?
        $stmt->execute([$username]);

        // 获取查询结果（一行数据）
        // $user 是数组，结构：['pwd' => '数据库里加密的密码']
        $user = $stmt->fetch();

        // 验证3：原密码是否正确
        // !$user：用户名不存在（理论上已登录不会出现）
        // !password_verify($oldpwd, $user['pwd'])：用户输入的原密码 和 数据库加密密码 不匹配
        if (!$user || !password_verify($oldpwd, $user['pwd'])) {
            $msg = "原密码错误！";
            goto END;
        }

        // 密码验证通过 → 对新密码进行加密
        // PASSWORD_DEFAULT：PHP推荐的默认加密算法（bcrypt），非常安全
        $new_pwd_hash = password_hash($newpwd, PASSWORD_DEFAULT);

        // 准备更新密码的SQL语句
        $update = $pdo->prepare("UPDATE reg_user SET pwd= ? WHERE username= ?");

        // 执行更新：传入 加密后的新密码、用户名
        $update->execute([$new_pwd_hash, $username]);

        // 修改密码成功 → 清空当前会话所有数据
        session_unset();
        // 销毁会话，强制用户重新登录
        session_destroy();

        // 弹出成功提示，然后跳转到登录页
        echo "<script>alert('密码修改成功！请重新登录');location.href='login.php';</script>";
        // 终止脚本
        exit;

        // 捕获数据库操作异常（如：数据库断连、SQL错误）
    } catch (PDOException $e) {
        // 把数据库错误信息赋值给提示变量
        // $e->getMessage()：获取具体错误内容
        $msg = "操作失败：" . $e->getMessage();
    }

    // goto 跳转的结束标记，验证不通过/出错时跳到这里
    END:
}
?>
<!-- 下面是 HTML 页面结构：修改密码的界面 -->
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <title>修改密码</title>
    <!-- 设置网页字符编码为UTF-8，防止中文乱码 -->
    <meta charset="utf-8">
    <style>
        /* 美拉德色系核心样式：定义颜色变量，方便统一修改 */
        :root {
            --main-brown: #8B4513; /* 牛皮棕 */
            --caramel: #CD853F; /* 焦糖色 */
            --light-brown: #DEB887; /* 浅棕 */
            --dark-brown: #5C3317; /* 深棕 */
            --cream: #F5F5DC; /* 米白 */
        }
        /* 全局样式初始化：清除默认边距、内边距，统一盒模型 */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: "Microsoft YaHei", sans-serif;
        }
        /* 页面背景、布局样式 */
        body {
            background-color: var(--cream);
            padding: 50px;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
        }
        /* 标题样式 */
        h2 {
            color: var(--dark-brown);
            margin-bottom: 30px;
            font-size: 24px;
        }
        /* 表单样式：白色背景、圆角、阴影、边框 */
        form {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(92, 51, 23, 0.2);
            width: 400px;
            border: 1px solid var(--light-brown);
            margin-bottom: 20px;
        }
        /* 提示信息样式：错误提示红色背景、文字居中 */
        .msg {
            color: #D2691E; /* 巧克力红 */
            margin-bottom: 20px;
            padding: 10px;
            background: rgba(210, 105, 30, 0.1);
            border-radius: 5px;
            text-align: center;
        }
        /* 段落间距 */
        p {
            margin-bottom: 15px;
        }
        /* 标签文字样式 */
        label {
            color: var(--dark-brown);
            font-weight: 600;
        }
        /* 密码输入框样式 */
        input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            margin-top: 5px;
            border: 1px solid var(--light-brown);
            border-radius: 5px;
            background: var(--cream);
            color: var(--dark-brown);
            font-size: 14px;
        }
        /* 输入框获得焦点时的高亮样式 */
        input[type="password"]:focus {
            outline: none;
            border-color: var(--caramel);
            box-shadow: 0 0 5px rgba(205, 133, 63, 0.3);
        }
        /* 提交按钮样式 */
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: var(--main-brown);
            color: white;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s ease;
            margin-top: 10px;
        }
        /* 鼠标悬停按钮时变色 */
        button:hover {
            background: var(--dark-brown);
        }
        /* 链接样式 */
        a {
            color: var(--main-brown);
            text-decoration: none;
            font-size: 14px;
            transition: color 0.3s ease;
        }
        /* 鼠标悬停链接样式 */
        a:hover {
            color: var(--dark-brown);
            text-decoration: underline;
        }
    </style>
</head>
<body>
<!-- 页面标题 -->
<h2>修改密码</h2>

<!-- 如果 $msg 不为空，显示错误/提示信息 -->
<?php if (!empty($msg)) echo "<p class='msg'>$msg</p>"; ?>

<!-- 修改密码表单：method=post 提交到当前页面 -->
<form method="post" action="">
    <!-- 原密码输入框，name=oldpwd，必填 -->
    <p>原密码：<input type="password" name="oldpwd" required></p>
    <!-- 新密码输入框，name=newpwd，必填 -->
    <p>新密码：<input type="password" name="newpwd" required></p>
    <!-- 确认新密码输入框，name=newpwd2，必填 -->
    <p>确认新密码：<input type="password" name="newpwd2" required></p>
    <!-- 提交按钮 -->
    <button type="submit">提交修改</button>
</form>

<!-- 返回欢迎页面链接 -->
<a href="welcome.php">返回欢迎页</a>
</body>
</html>