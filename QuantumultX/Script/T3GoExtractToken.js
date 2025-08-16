
// 提取请求头中的 token
let Token = $request.headers['token'];

// 检查是否成功获取到 token
if (Token) {
  // 记录日志，换行后打印 token 值
  console.log("T3出行App\n获取到请求头中的 Token:\n" + Token);
  // 发送通知（可选）
  $notify("T3出行App", "Token 获取成功", Token);
} else {
  console.log('T3出行App\n没有获取到请求头中的 Token ，刷新一下签到、积分页面试试！');
  $notify("T3出行App", "没有获取到请求头中的 Token ，刷新一下签到、积分页面试试！");
}

// 结束响应处理并返回原始响应体
$done({});