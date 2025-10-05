// 目的: 提取请求头中的 User-Agent 和响应体中的 openid

(function() {
    // 获取请求头
    const headers = $request.headers;
    const userAgent = headers['User-Agent'] || null;

    // 获取响应体
    let body = $response.body;
    let openid = null;

    try {
        // 解析响应体为 JSON
        const jsonBody = JSON.parse(body);
        // 从 data.infa.openid 中提取 openid
        openid = jsonBody.data?.infa?.openid || null;
    } catch (e) {
        console.log('解析响应体错误: ' + e);
    }

    // 检查是否提取到两个值
    if (!userAgent || !openid) {
        // 如果任一值缺失，通知用户重新打开小程序
        $notify('提取失败', '', '无法提取 User-Agent 或 OpenID，请重新打开小程序并点击“我的”。');
    } else {
        // 通知提取到的值
        const message = `User-Agent: ${userAgent}\nOpenID: ${openid}`;
        $notify('提取成功', '', message);
    }

    // 原样返回响应体
    $done({ body });
})();