// ExtractURL.js
// 提取 Cookie
let URL = $request.url;

// 检查是否成功获取到 Cookie
if (URL) {
  // 记录日志，换行后打印 Cookie 值
  console.log("顺丰速运获取到的 URL:\n" + URL);
  // 发送通知（可选）
  $notify("顺丰速运", "URL 获取成功", URL);
} else {
  console.log('没有获取到URL，刷新一下页面试试！');
  $notify("顺丰速运", "没有获取到URL，刷新一下页面试试！");
}

// 结束响应处理并返回原始响应体
$done({});