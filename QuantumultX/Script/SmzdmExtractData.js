// Quantumult X 重写脚本
// URL: https://h5.smzdm.com/user/safepass/ajax_update_safepass
// 目的: 提取User-Agent、Cookie和en_safepass，并拼接Cookie;en_safepass=值; 通知结果

(function() {
    // 获取请求头
    const headers = $request.headers;
    const userAgent = headers['User-Agent'] || null;
    const cookie = headers['Cookie'] || null;

    // 获取并解析请求体 (application/x-www-form-urlencoded)
    let body = $request.body || '';
    let enSafepassValue = null;

    if (body) {
        // 解析URL编码的表单数据
        const params = new URLSearchParams(body);
        enSafepassValue = params.get('en_safepass') || null;
    }

    // 检查是否提取到所有值
    if (!userAgent || !cookie || !enSafepassValue) {
        // 提取失败通知
        $notify('什么值得买', '提取失败', '无法提取User-Agent、Cookie或en_safepass，请重新打开App并尝试设置安全密码。');
    } else {
        // 拼接: Cookie;en_safepass=值;
        const enSafepassFull = `en_safepass=${enSafepassValue};`;
        const combined = `${cookie};${enSafepassFull}`;

        // 通知结果
        const message = `User-Agent: \n${userAgent}\n\n拼接结果: \n${combined}`;
        $notify('什么值得买', '提取成功', message);
    }

    // 原样返回请求（不修改）
    $done({ ...$request });
})();
