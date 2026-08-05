/**
 * @fileoverview Quantumult X 提取 Geely refreshToken & gl_dev_id 脚本
 */

const url = $request.url;
const headers = $request.headers;

// 1. 从 URL 中正则匹配提取 refreshToken
const refreshTokenMatch = url.match(/[?&]refreshToken=([^&]+)/);
const refreshToken = refreshTokenMatch ? refreshTokenMatch[1] : null;

// 2. 从 Headers 中提取 gl_dev_id（处理 Header 键名可能的大小写差异）
let glDevId = null;
if (headers) {
    for (const key in headers) {
        if (key.toLowerCase() === 'gl_dev_id') {
            glDevId = headers[key];
            break;
        }
    }
}

// 3. 校验并拼接保存
if (refreshToken && glDevId) {
    const combinedValue = `${refreshToken}&${glDevId}`;
    
    // 保存到 Quantumult X 的持久化存储中（键名为 geely_refresh_info）
    $prefs.setValueForKey(combinedValue, "geely_refresh_info");
    
    // 发送成功通知
    $notify("吉利 Token 提取成功 🎉", "已成功拼接参数", combinedValue);
    console.log(`[Geely Extracted] ${combinedValue}`);
} else {
    console.log(`[Geely Extract Failed] refreshToken: ${refreshToken}, gl_dev_id: ${glDevId}`);
}

// 脚本执行完毕，放行请求
$done({});
