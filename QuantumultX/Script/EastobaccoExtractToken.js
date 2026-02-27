// Quantumult X 重写脚本 - 东烟草（东烟）多位置 token 提取
// 目标域名：eapp.eastobacco.com / eshop.eastobacco.com / eappimg.eastobacco.com
// 提取位置：1. 请求体中的 token=xxx  2. Referer 中的 token=xxx 参数
// 优先级：请求体 > Referer

(function () {
  // ────────────────────────────────────────────────
  // 1. 初始化变量
  // ────────────────────────────────────────────────
  let token = null;
  let source = "未找到";
  const headers = $request.headers || {};
  const referer = headers["Referer"] || headers["referer"] || "";

  // ────────────────────────────────────────────────
  // 2. 优先尝试从请求体提取（POST 表单常见）
  // ────────────────────────────────────────────────
  if ($request.body) {
    let body = $request.body;

    // 记录完整请求体（调试用，可注释）
    // console.log("东烟草 请求体:\n" + body);

    // 匹配 token=xxx（支持 urlencoded 格式）
    const tokenMatch = body.match(/token=([^&]+)/i);
    if (tokenMatch && tokenMatch[1]) {
      token = tokenMatch[1];
      source = "请求体 (body)";
    }
  }

  // ────────────────────────────────────────────────
  // 3. 如果请求体没找到，再尝试从 Referer 提取
  // ────────────────────────────────────────────────
  if (!token && referer) {
    const refMatch = referer.match(/[?&]token=([^&?#]+)/i);
    if (refMatch && refMatch[1]) {
      token = refMatch[1];
      source = "Referer 查询参数";
    }
  }

  // ────────────────────────────────────────────────
  // 4. 根据结果发送通知
  // ────────────────────────────────────────────────
  if (token) {
    const message = 
      `提取到 token：${token}\n` +
      `来源：${source}\n\n` +
      (source.includes("请求体") ? `完整请求体片段：\n${$request.body?.substring(0, 300) || "无"}` : 
       `完整 Referer：\n${referer}`);

    $notify(
      "东烟 Token 提取成功",
      `位置：${source}`,
      message,
      "https://eshop.eastobacco.com"
    );

    console.log(`[东烟] 成功提取 token: ${token}  (从 ${source})`);
  } else {
    let reason = "本次请求既无请求体 token，也无 Referer 中的 token 参数";

    if (!$request.body && !referer) {
      reason = "缺少请求体 & 缺少 Referer 头";
    } else if (!$request.body) {
      reason = "本次为 GET 请求，无请求体";
    } else if (!referer) {
      reason = "请求头缺少 Referer";
    }

    $notify(
      "东烟 Token 提取失败",
      "",
      `${reason}\n\n` +
      `建议：\n` +
      `1. 确认已开启 HTTPS 解密\n` +
      `2. 重新进入商品列表页\n` +
      `3. 尝试刷新或切换分类再试`,
      ""
    );

    console.log("[东烟] " + reason);
  }

  // ────────────────────────────────────────────────
  // 5. 不修改请求/响应，直接放行
  // ────────────────────────────────────────────────
  $done({});
})();