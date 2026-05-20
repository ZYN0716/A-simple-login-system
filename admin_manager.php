<?php
// ===================== 1. 会话初始化 + 登录权限验证 =====================
// 启动PHP会话（用来保存管理员登录状态）
session_start();

// 判断：会话中是否存在 "username" 字段（即管理员是否登录）
// !isset() = 如果不存在
if(!isset($_SESSION['username'])){
    // 未登录 → 强制跳转到登录页
    header('Location: login.php');
    // 跳转后立即终止脚本执行，防止后面代码继续运行
    exit;
}

// ===================== 2. 引入外部工具文件 =====================
// 引入安全过滤函数文件（用来过滤用户输入，防XSS攻击）
require_once "test_input.php";
// 引入数据库连接文件（里面定义了 $pdo 数据库连接对象）
include "pdu_connect.php";

// ===================== 3. 定义全局提示信息变量 =====================
// $successMsg：存储【删除操作】的成功提示文字（字符串类型）
$successMsg="";
// $uploadMsg：存储【图片上传】的所有提示信息（数组类型，可存多条）
$uploadMsg=[];

// ===================== 4. 功能1：按用户名删除该用户所有留言 =====================
// 判断：URL地址栏是否传了 ?username=xxx 参数
if(isset($_GET['username'])){
    // 接收URL中的用户名参数
    $username = $_GET['username'];

    // SQL预编译语句：从 message 表中删除 用户名=指定值 的所有数据
    // :username 是PDO预编译占位符，防SQL注入
    $sql = "DELETE FROM message WHERE username=:username";
    // 准备SQL语句（PDO安全写法）
    $stmt = $pdo->prepare($sql);
    // 执行SQL，把参数绑定到占位符
    $stmt->execute(['username' => $username]);

    // 赋值成功提示文字
    $successMsg="成功删除【".$username."】的所有留言！";
}

// ===================== 5. 功能2：按留言ID删除单条留言 =====================
// 判断：URL地址栏是否传了 ?del_id=xxx 参数
if(isset($_GET['del_id'])){
    // 接收URL中的留言ID参数
    $id = $_GET['del_id'];
    // SQL：删除 message 表中 ID=指定值 的单条数据
    $sql = "DELETE FROM message WHERE id=:id";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['id' => $id]);

    // 赋值成功提示
    $successMsg = "单条留言删除成功！";
}

// ===================== 6. 功能3：管理员批量上传图片（核心逻辑） =====================
// 判断：当前请求是否为 POST 方式（即表单提交）
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // 判断：是否没有选择任何文件（$_FILES['file']['name'][0] 为空）
    if(empty($_FILES['file']['name'][0])){
        // 把提示信息存入上传提示数组
        $uploadMsg[] = "请选择要上传的图片！";
    }

    // 获取上传文件的总数量
    $filecount = count($_FILES['file']['name']);

    // 定义允许上传的图片后缀 + 对应的真实MIME类型（安全校验）
    $allowed = [
            'jpg'=> 'image/jpeg',
            'jpeg'=> 'image/jpeg',
            'gif'=> 'image/gif',
            'png'=> 'image/png',
    ];

    // 循环：逐个处理每一张上传的图片
    for ($i=0; $i < $filecount; $i++) {
        // 获取当前文件的 原始文件名
        $name = $_FILES['file']['name'][$i];
        // 获取当前文件的 临时存储路径（PHP上传后自动生成的临时文件）
        $tmpname = $_FILES['file']['tmp_name'][$i];
        // 获取文件MIME类型（浏览器上传时带的类型）
        $type = $_FILES['file']['type'][$i];
        // 获取文件大小（字节）
        $size = $_FILES['file']['size'][$i];
        // 获取文件后缀名，并转小写（.jpg/.png等）
        $ext=strtolower(pathinfo($name, PATHINFO_EXTENSION));

        // 如果文件名为空，跳过本次循环（不处理）
        if (empty($name)) continue;

        // ===================== 安全校验1：验证文件真实类型（防篡改） =====================
        // 打开文件信息检测
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        // 获取文件【真实的MIME类型】（读取文件内容，不是靠后缀判断）
        $realMime = finfo_file($finfo, $tmpname);
        // 关闭文件检测
        finfo_close($finfo);

        // 判断：后缀不在允许列表 或 真实类型不匹配 → 不允许上传
        if (!array_key_exists($ext, $allowed) || $allowed[$ext] !== $realMime) {
            $uploadMsg[] = "文件 $name 类型不合法！";
            // 跳过，处理下一个文件
            continue;
        }

        // ===================== 安全校验2：文件大小限制（最大2MB） =====================
        $maxsize=2*1024*1024; // 2MB = 2*1024KB*1024字节
        if($size > $maxsize){
            $uploadMsg[] = "文件 $name 超过2MB限制！";
            continue;
        }

        // ===================== 安全校验3：验证是否为真实图片 + 尺寸限制 =====================
        // @ 符号：抑制错误提示（防止非图片文件报错暴露路径）
        $info=@getimagesize($tmpname);
        // 判断：不是图片 或 宽/高≥4000像素 → 不允许
        if($info==false || $info[0]>=4000||$info[1]>=4000){
            $uploadMsg[] = "文件 $name 不是合法图片或尺寸过大！";
            continue;
        }

        // ===================== 准备上传目录 =====================
        $dir = "upl/"; // 上传到 upl 文件夹
        // 如果目录不存在，创建目录（0777最高权限，true递归创建）
        if(!file_exists($dir)){
            mkdir($dir, 0777, true);
        }

        // ===================== 生成随机文件名（防止重名+防猜解） =====================
        // bin2hex(random_bytes(16))：生成32位随机字符串
        $new_name = bin2hex(random_bytes(16)) . "." . $ext;
        // 最终文件保存路径 = 目录 + 新文件名
        $dest = $dir . $new_name;

        // ===================== 移动临时文件到目标目录（正式上传） =====================
        if (move_uploaded_file($tmpname, $dest)) {
            // 上传成功提示
            $uploadMsg[] = "✅ 文件 $name 上传成功：" . $dest;
        } else {
            // 上传失败提示
            $uploadMsg[] = "❌ 文件 $name 上传失败";
        }
    }
}
?>

<!-- ===================== HTML前端页面：管理员操作界面 ===================== -->
<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <meta charset="UTF-8">
    <title>管理员管理</title>
    <style>
        /* 美拉德色系核心样式 */
        :root {
            --main-brown: #8B4513; /* 牛皮棕 */
            --caramel: #CD853F; /* 焦糖色 */
            --light-brown: #DEB887; /* 浅棕 */
            --dark-brown: #5C3317; /* 深棕 */
            --cream: #F5F5DC; /* 米白 */
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: "Microsoft YaHei", sans-serif;
        }
        body {
            background-color: var(--cream);
            padding: 30px 50px;
            max-width: 1200px;
            margin: 0 auto;
        }
        h2, h3 {
            color: var(--dark-brown);
            margin: 20px 0;
        }
        a {
            color: var(--main-brown);
            text-decoration: none;
            transition: color 0.3s ease;
            margin-right: 15px;
        }
        a:hover {
            color: var(--dark-brown);
            text-decoration: underline;
        }
        .success-msg {
            color: var(--main-brown);
            padding: 10px;
            background: rgba(139, 69, 19, 0.1);
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid var(--light-brown);
        }
        .user-item, .message-item {
            background: white;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid var(--light-brown);
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .upload-section {
            background: white;
            padding: 20px;
            border-radius: 5px;
            border: 1px solid var(--light-brown);
            margin-top: 30px;
        }
        input[type="file"] {
            padding: 8px;
            margin: 10px 0;
            border: 1px solid var(--light-brown);
            border-radius: 5px;
            background: var(--cream);
        }
        input[type="submit"] {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background: var(--main-brown);
            color: white;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        input[type="submit"]:hover {
            background: var(--dark-brown);
        }
        .upload-msg {
            margin: 10px 0;
            color: var(--dark-brown);
            padding: 8px;
            border-radius: 3px;
        }
        hr {
            border: none;
            border-top: 1px solid var(--light-brown);
            margin: 25px 0;
        }
    </style>
</head>
<body>
<h2>管理员 - 留言用户管理</h2>
<!-- 退出登录链接 -->
<a href="logout.php">退出登录</a>
<!-- 管理注册用户链接 -->
<a href="admin_reuser.php">管理注册用户</a>

<!-- 如果有删除成功提示，则显示 -->
<?php  if($successMsg) :?>
    <p class="success-msg"><?php echo $successMsg; ?></p>
<?php endif; ?>

<h3>留言用户列表</h3>
<?php
// SQL：查询 message 表中【不重复的用户名】，按用户名排序
$sql = "SELECT DISTINCT username FROM message ORDER BY username ";
// 执行查询
$stmt = $pdo->query($sql);
// 判断：是否有数据
if ($stmt->rowCount() > 0) {
    // 循环输出每一个用户名
    while($row = $stmt->fetch()) {
        $user = $row["username"];
        ?>
        <div class="user-item">
            <span>用户名：<?php echo $user; ?></span>
            <!-- 点击链接：带用户名参数，执行删除该用户所有留言 -->
            <!-- onclick：弹出确认框，防止误删 -->
            <a href="?username=<?php echo $user; ?>"
               onclick="return confirm('确定要删除【<?php echo $user?>】的所有留言吗？')">删除该用户所有留言</a>
        </div>
        <?php
    }
}else{
    echo "暂无留言用户";
}
?>

<hr>
<h3>所有留言（管理员可删除单条留言）</h3>
<?php
// SQL：查询所有留言，按创建时间倒序（最新的在最上面）
$sql ="SELECT * FROM message ORDER BY create_time DESC ";
$stmt = $pdo->query($sql);
if ($stmt->rowCount() > 0) {
    // 循环输出每一条留言
    while($row = $stmt->fetch()) {
        echo "<div class='message-item'>";
        echo "<div>";
        echo "ID：".$row['id']."<br>";
        echo "用户：".$row['username']."<br>";
        echo "内容：".$row['content']."<br>";
        echo "时间：".$row['create_time']."<br>";
        echo "</div>";
        // 带ID参数，删除单条留言
        echo "<a href='?del_id=" . $row['id'] . "' onclick='return confirm(\"确定删除这条？\")'>删除本条</a>";
        echo "</div>";
    }
}else{
    echo "暂无留言";
}
?>

<!-- 图片上传表单区域 -->
<div class="upload-section">
    <h3>管理员图片上传</h3>
    <!-- 上传表单必须加：enctype="multipart/form-data" -->
    <form method="post" action="" enctype="multipart/form-data">
        <!-- name="file[]" 数组格式，支持多文件上传 -->
        <input type="file" name="file[]" multiple accept="image/*">
        <input type="submit" value="上传图片">
    </form>

    <!-- 循环输出所有上传提示信息 -->
    <?php foreach ($uploadMsg as $msg):?>
        <p class="upload-msg"><?php echo test_input($msg)?></p>
    <?php endforeach;?>
</div>
</body>
</html>