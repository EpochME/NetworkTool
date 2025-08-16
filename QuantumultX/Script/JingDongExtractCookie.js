/*
  获取京东网页版 Cookie 原始值和关键值
*/


// ExtractCookie.js

// 获取请求头 Cookie 原始值
let cookie = $request.headers['Cookie'] || $request.headers['cookie'];

// 检查是否成功获取到 Cookie
if (cookie) {
  // 记录日志，换行后打印 Cookie 值
  console.log("获取到京东网页版 Cookie 完整值\n\n" + cookie);
  // 发送通知（可选）
  //$notify("京东网页版", "获取到完整 Cookie ", cookie);
}

// 获取请求头 Cookie 的关键值

let originalContent = cookie;

// 正则表达式匹配 pt_key 和 pt_pin 的值
const ptKeyMatch = originalContent.match(/pt_key=([^;]+);?/);
const ptPinMatch = originalContent.match(/pt_pin=([^;]+);?/);

if (ptKeyMatch && ptPinMatch) {
  const ptKey = ptKeyMatch[1];
  const ptPin = ptPinMatch[1];
  const output = `pt_key=${ptKey};pt_pin=${ptPin};`;
  console.log("京东网页版\n获取到 Cookie 关键值\n" + output);
  $notify("京东网页版", "获取到 Cookie 关键值", output);
} else {
  console.log('pt_key 和 pt_pin 未找到');
  $notify("京东网页版", "未找到 Cookie 关键值，刷新一下页面试试！");
}
$done();
