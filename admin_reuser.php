<?php
// ======================== 1. 会话初始化与登录验证 ========================
// 启动PHP会话机制：用于读取/存储管理员登录状态（必须在任何输出前调用）
session_start();

// 判断：会话中不存在 admin_login 标识 → 代表管理员未登录
if (!isset($_SESSION['admin_login'])) {
    // 强制跳转到登录页面 login.php
    header('Location: login.php');
    // 终止后续所有代码执行（防止未登录用户看到管理页面）
    exit;
}

// ======================== 2. 引入外部依赖文件 ========================
// 引入自定义函数文件：test_input.php 通常用于【过滤/安全处理用户输入】
require_once "test_input.php";

// 引入数据库连接文件：pdu_connect.php 里面定义了 $pdo 数据库连接对象
include "pdu_connect.php";

// ======================== 3. 定义全局提示信息变量 ========================
// 成功提示变量：存储操作成功后的文字（如：删除成功、修改成功）
$successMsg = "";
// 错误提示变量：存储操作失败/禁止操作的文字（如：不能删除自己、删除失败）
$errorMsg = "";

// ======================== 4. 处理【删除用户】请求 ========================
// 判断：URL 地址栏中存在 del_id 参数 → 代表用户点击了【删除用户】按钮
if (isset($_GET['del_id'])) {
    // 获取要删除的用户ID（从URL参数中获取，如 ?del_id=5）
    $del_id = $_GET['del_id'];

    // SQL查询：根据ID查询 message 表（作用：校验是否是当前登录用户自己）
    $sql = "SELECT * FROM reg_user WHERE id=:id";
    // PDO预处理SQL：防止SQL注入（安全操作数据库）
    $stmt = $pdo->prepare($sql);
    // 执行预处理SQL，绑定参数 :id = $del_id
    $stmt->execute(['id' => $del_id]);
    // 获取查询结果：返回单条用户数据（数组格式）
    $user = $stmt->fetch();

    // 安全校验：如果查到数据 + 要删除的用户 = 当前登录管理员 → 禁止删除自己
    if ($user && $_SESSION['username'] == $user['username']) {
        $errorMsg = "不能删除自己";
        // 跳转到代码末尾的 END 标记：跳过删除逻辑，直接结束本段代码
        goto END;
    }

    // SQL删除语句：从 reg_user 表中删除指定ID的用户（真正的用户表）
    $sql = "DELETE FROM reg_user WHERE id=:id";
    $stmt = $pdo->prepare($sql);
    // 执行删除，绑定ID参数
    $stmt->execute(['id' => $del_id]);

    // 判断：受影响行数 > 0 → 删除成功
    if ($stmt->rowCount() > 0) {
        $successMsg = "删除成功";
    } else {
        $errorMsg = "删除失败";
    }
}

// ======================== 5. 处理【修改用户权限】请求 ========================
// 判断：表单提交了 change_role 参数 → 代表点击了【保存权限】按钮
if (isset($_POST['change_role'])) {
    // 获取要修改权限的用户ID（从表单隐藏域提交）
    $id = $_POST['id'];
    // 获取新权限值：强制转为整数（0=普通用户，1=管理员）
    $new_role = (int)$_POST['role'];

    // SQL查询：根据ID查询用户名
    $sql = "SELECT username FROM reg_user WHERE id=?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$id]);
    $user = $stmt->fetch();

    // 安全校验：不能修改自己的权限
    if ($user['username'] == $_SESSION['username']) {
        $errorMsg = "无法修改自己的权限";
    } else {
        // SQL更新语句：修改用户角色权限
        $sql = "UPDATE reg_user SET role=? WHERE id=?";
        $stmt = $pdo->prepare($sql);
        // 执行更新：参数顺序 [新权限, 用户ID]
        $stmt->execute([$new_role, $id]);
        $successMsg = "修改成功";
    }

// END标记：配合上面的 goto END 使用，跳过删除逻辑
    END:
}
?>
<!-- ======================== 前端HTML页面 ======================== -->
<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <!-- 网页编码：防止中文乱码 -->
    <meta charset="UTF-8">
    <!-- 网页标题 -->
    <title>管理员注册用户管理</title>
    <style>
        /* 美拉德色系核心样式：定义CSS变量，方便统一修改颜色 */
        :root {
            --main-brown: #8B4513; /* 牛皮棕 */
            --caramel: #CD853F; /* 焦糖色 */
            --light-brown: #DEB887; /* 浅棕 */
            --dark-brown: #5C3317; /* 深棕 */
            --cream: #F5F5DC; /* 米白 */
        }
        /* 全局样式重置：清除默认边距，统一盒模型 */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: "Microsoft YaHei", sans-serif;
        }
        /* 页面背景、内边距、居中 */
        body {
            background-color: var(--cream);
            padding: 30px 50px;
            max-width: 1000px;
            margin: 0 auto;
        }
        /* 标题样式 */
        h2, h3 {
            color: var(--dark-brown);
            margin: 20px 0;
        }
        /* 链接默认样式 + 鼠标悬浮效果 */
        a {
            color: var(--main-brown);
            text-decoration: none;
            transition: color 0.3s ease;
            margin-bottom: 20px;
            display: inline-block;
        }
        a:hover {
            color: var(--dark-brown);
            text-decoration: underline;
        }
        /* 成功提示框样式 */
        .success-msg {
            color: var(--main-brown);
            padding: 10px;
            background: rgba(139, 69, 19, 0.1);
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid var(--light-brown);
        }
        /* 错误提示框样式 */
        .error-msg {
            color: #D2691E;
            padding: 10px;
            background: rgba(210, 105, 30, 0.1);
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid var(--light-brown);
        }
        /* 用户卡片容器：每个用户一行 */
        .user-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--light-brown);
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        /* 用户信息展示区域 */
        .user-info {
            flex: 1;
            color: var(--dark-brown);
        }
        /* 用户操作按钮区域：修改权限 + 删除 */
        .user-actions {
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: nowrap;
        }
        /* 下拉选择框样式 */
        select {
            padding: 8px 12px;
            border: 1px solid var(--light-brown);
            border-radius: 5px;
            background: var(--cream);
            color: var(--dark-brown);
            cursor: pointer;
            height: 38px;
            box-sizing: border-box;
        }
        /* 按钮样式 */
        button {
            padding: 8px 15px;
            border: none;
            border-radius: 5px;
            background: var(--main-brown);
            color: white;
            cursor: pointer;
            transition: background 0.3s ease;
            height: 38px;
            line-height: 1;
        }
        button:hover {
            background: var(--dark-brown);
        }
        /* 删除链接样式 */
        .delete-link {
            color: #D2691E;
            display: inline-flex;
            align-items: center;
            height: 38px;
            padding: 0 5px;
        }
        .delete-link:hover {
            color: var(--dark-brown);
            text-decoration: underline;
        }
        /* 分割线样式 */
        hr {
            border: none;
            border-top: 1px solid var(--light-brown);
            margin: 15px 0;
        }
    </style>
</head>
<body>
<h2>管理员注册用户管理</h2>
<!-- 退出管理页面链接 -->
<a href="admin_manager.php">退出注册用户管理</a>

<!-- 如果有成功信息，显示成功提示框 -->
<?php if ($successMsg): ?>
    <p class="success-msg"><?php echo $successMsg; ?></p>
<?php endif; ?>

<!-- 如果有错误信息，显示错误提示框 -->
<?php if ($errorMsg): ?>
    <p class="error-msg"><?php echo $errorMsg; ?></p>
<?php endif; ?>

<h3>所有注册用户</h3>

<?php
// 查询 reg_user 表中所有用户数据
$sql = "SELECT * FROM reg_user";
// 执行查询
$stmt = $pdo->query($sql);
// 循环输出每一个用户
while ($row = $stmt->fetch()) {
    ?>
    <div class="user-card">
        <div class="user-info">
            <!-- 输出用户ID -->
            ID：<?PHP echo $row['id']; ?><br>
            <!-- 输出用户名 -->
            用户名：<?PHP echo $row['username']; ?><br>
            <!-- 三元运算：role=1 显示管理员，否则显示普通用户 -->
            角色：<?php echo $row['role'] == 1 ? "管理员" : "普通用户"; ?>
        </div>
        <div class="user-actions">
            <!-- 修改权限表单：POST提交到当前页面 -->
            <form method="post" action="" style="display: inline; margin: 0;">
                <!-- 隐藏域：传递用户ID -->
                <input type="hidden" name="id" value="<?php echo $row['id']; ?>">
                <!-- 权限选择下拉框 -->
                <select name="role">
                    <option value="0" <?php if ($row['role'] == 0) echo "selected"; ?>>普通用户</option>
                    <option value="1" <?php if ($row['role'] == 1) echo "selected"; ?>>管理员用户</option>
                </select>
                <!-- 提交按钮：触发修改权限逻辑 -->
                <button type="submit" name="change_role">保存</button>
            </form>
            <!-- 删除链接：携带用户ID，点击弹出确认框 -->
            <a href="?del_id=<?php echo $row['id']; ?>" class="delete-link"
               onclick="return confirm('确定要删除用户【<?php echo $row['username']; ?>】吗？')">删除用户</a>
        </div>
    </div>
<?php } ?>
</body>
</html>