/*
  获取eapp.eastobacco.com请求体中的token值
*/

// ExtractToken.js

// 获取请求体
let body = $request.body;

// 检查是否成功获取到请求体
if (body) {
  // 记录日志，换行后打印请求体
  console.log("获取到东方烟草报App请求体\n\n" + body);
  // 发送通知（可选，注释掉）
  //$notify("eapp.eastobacco.com", "获取到完整请求体", body);
}

// 提取请求体中的token值
let originalContent = body;

// 正则表达式匹配token的值
const tokenMatch = originalContent.match(/token=([^&]+)/);

if (tokenMatch) {
  const token = tokenMatch[1];
  const output = `token=${token}`;
  console.log("东方烟草报App\n获取到token值\n" + output);
  $notify("东方烟草报App", "获取到请求体token值", output);
} else {
  console.log('东方烟草报App token未找到');
  $notify("东方烟草报App", "未找到token值，请检查请求体！");
}
$done();