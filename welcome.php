<?php
// 1. 启动PHP会话机制：必须写在最顶部！作用是读取/操作服务器端的用户登录会话数据
// 会话：服务器临时存储当前用户信息的容器，关闭浏览器/超时会销毁
session_start();

// 2. 登录权限验证核心逻辑
// isset()：判断变量是否存在且不为null
// empty()：判断变量是否为空（空字符串、0、null、false都算空）
// 逻辑：如果会话中没有用户名 或者 用户名为空 → 未登录
if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
    // 3. 未登录：强制跳转到登录页面（login.php）
    // header()：PHP头部函数，用于发送HTTP跳转指令
    header("Location: login.php");
    // 4. 终止后续所有代码执行（必须加！防止未登录用户看到页面内容）
    exit;
}
?>
<!-- HTML5文档声明：告诉浏览器这是标准HTML5页面 -->
<!DOCTYPE html>
<!-- 页面根标签，lang="zh-CN" 表示页面语言为简体中文 -->
<html lang="zh-CN">
<!-- 页面头部：存放页面配置、样式、标题，不直接显示在页面上 -->
<head>
    <!-- 字符编码：设置页面使用UTF-8编码，防止中文乱码 -->
    <meta charset="UTF-8">
    <!-- 页面标题：浏览器标签栏显示的文字 -->
    <title>欢迎页面</title>
    <!-- CSS样式标签：编写页面的外观、颜色、布局、字体等样式 -->
    <style>
        /* 美拉德色系核心样式：CSS变量定义，方便统一修改颜色 */
        /* :root 根选择器：定义全局可用的CSS变量，变量名以--开头 */
        :root {
            --main-brown: #8B4513; /* 牛皮棕：主按钮颜色 */
            --caramel: #CD853F;    /* 焦糖色：管理员专用按钮颜色 */
            --light-brown: #DEB887;/* 浅棕：边框颜色 */
            --dark-brown: #5C3317; /* 深棕：文字主颜色 */
            --cream: #F5F5DC;      /* 米白：页面背景色 */
        }

        /* 全局样式重置：清除所有标签默认的内外边距，统一盒子模型 */
        * {
            margin: 0;          /* 外边距：标签与外部元素的距离 */
            padding: 0;         /* 内边距：标签内容与边框的距离 */
            box-sizing: border-box;/* 盒子模型：边框和内边距不撑开元素宽度 */
            font-family: "Microsoft YaHei", sans-serif;/* 字体：优先微软雅黑 */
        }

        /* body标签样式：整个页面的身体，控制页面整体布局 */
        body {
            background-color: var(--cream);/* 背景色：使用上面定义的米白变量 */
            display: flex;                 /* 弹性布局：让子元素居中 */
            flex-direction: column;         /* 子元素垂直排列 */
            justify-content: center;        /* 垂直居中 */
            align-items: center;            /* 水平居中 */
            min-height: 100vh;              /* 最小高度：占满整个屏幕高度 */
            color: var(--dark-brown);       /* 默认文字颜色：深棕 */
        }

        /* 欢迎容器样式：包裹所有页面内容的白色盒子 */
        .welcome-container {
            background: white;              /* 背景白色 */
            padding: 50px;                  /* 内边距50px：内容和边框留空隙 */
            border-radius: 10px;            /* 圆角：边角变圆，半径10px */
            box-shadow: 0 4px 8px rgba(92, 51, 23, 0.2);/* 阴影：立体效果 */
            border: 1px solid var(--light-brown);/* 边框：1px 实线 浅棕 */
            text-align: center;             /* 文字水平居中 */
        }

        /* 一级标题样式：欢迎回来！ */
        h1 {
            color: var(--main-brown);       /* 文字颜色：牛皮棕 */
            margin-bottom: 30px;            /* 底部外边距：和下方内容留30px空隙 */
            font-size: 32px;                /* 字体大小32像素 */
        }

        /* 用户信息区域样式：用户名、身份展示 */
        .user-info {
            font-size: 18px;                /* 字体大小18像素 */
            margin-bottom: 40px;            /* 底部外边距40px */
            color: var(--dark-brown);       /* 文字颜色：深棕 */
        }

        /* 按钮组样式：所有按钮的父容器 */
        .btn-group {
            display: flex;                  /* 弹性布局 */
            flex-direction: column;         /* 按钮垂直排列 */
            gap: 15px;                      /* 按钮之间的间距15px */
            width: 300px;                   /* 容器宽度固定300px */
        }

        /* 所有按钮通用样式 */
        button {
            padding: 12px 20px;             /* 内边距：上下12px，左右20px */
            border: none;                   /* 清除按钮默认边框 */
            border-radius: 5px;             /* 按钮圆角5px */
            background: var(--main-brown); /* 背景色：牛皮棕 */
            color: white;                   /* 文字颜色白色 */
            font-size: 16px;                /* 字体大小16像素 */
            cursor: pointer;                /* 鼠标悬浮：变成小手样式 */
            transition: background 0.3s ease;/* 过渡动画：背景色渐变0.3秒 */
        }

        /* 按钮悬浮样式：鼠标放上去的效果 */
        button:hover {
            background: var(--dark-brown);  /* 背景色变为深棕 */
        }

        /* 管理员专用按钮样式：单独覆盖默认按钮样式 */
        .admin-btn {
            background: var(--caramel);     /* 背景色：焦糖色 */
        }

        /* 管理员按钮悬浮效果 */
        .admin-btn:hover {
            background: var(--main-brown);   /* 背景色变回牛皮棕 */
        }
    </style>
</head>
<!-- 页面主体：所有用户能看到的内容都写在这里 -->
<body>
<!-- 欢迎内容容器：class对应CSS样式 -->
<div class="welcome-container">
    <!-- 一级标题 -->
    <h1>欢迎回来！</h1>
    <!-- 用户信息展示区域 -->
    <div class="user-info">
        <!-- 输出用户名：htmlspecialchars() 防XSS攻击，安全输出特殊字符 -->
        用户名：<?php echo htmlspecialchars($_SESSION['username']); ?><br>
        <!-- 三元运算符：判断角色，1=管理员，其他=普通用户 -->
        身份：<?php echo $_SESSION['role'] == 1 ? "管理员" : "普通用户"; ?>
    </div>
    <!-- 按钮组容器 -->
    <div class="btn-group">
        <!-- 留言板按钮：点击跳转到message.php -->
        <button onclick="window.location.href='message.php'">进入留言板</button>
        <!-- 修改密码按钮：点击跳转到welpwd.php -->
        <button onclick="window.location.href='welpwd.php'">修改密码</button>

        <!-- PHP条件判断：只有角色=1（管理员）才显示这个按钮 -->
        <?php if ($_SESSION['role'] == 1): ?>
            <button class="admin-btn" onclick="window.location.href='admin_manager.php'">管理员管理</button>
        <?php endif; ?>

        <!-- 退出登录按钮：点击跳转到logout.php -->
        <button onclick="window.location.href='logout.php'">退出登录</button>
    </div>
</div>
</body>
</html>