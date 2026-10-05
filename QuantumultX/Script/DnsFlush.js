/**
 * ====================================================================
 * Quantumult X - DNS 缓存自动清理脚本
 * ====================================================================
 * 
 * 💡【为什么需要清理 DNS 缓存？】
 *   DNS 缓存用于暂存域名与 IP 地址的对应关系。在移动设备频繁切换网络环境
 *   （如从 Wi-Fi 切换至 5G、连接/断开 Tailscale 或在不同的节点策略间切换）时，
 *   旧的 DNS 缓存记录可能会失效或解析到非最优 IP，导致出现网页打不开、加载缓慢、
 *   分流策略不生效或节点报网络错误等问题。
 *
 * ⚖️【清理 DNS 缓存的优缺点】
 *   - 优点：
 *     1. 解决网络环境切换后的域名解析滞后与连接卡顿问题。
 *     2. 保证 Quantumult X 的分流规则能够实时命中最新解析到的最佳 IP。
 *     3. 强制刷空无效或受污染的 DNS 记录，提升网络稳定性。
 *   - 缺点：
 *     1. 刷新后的首次域名访问需要重新向 DNS 服务器发起查询，会带来微毫秒级的首包延迟。
 *     2. 若 Cron 执行频率设定过高（如几分钟一次），会造成不必要的性能开销与解析延迟。
 *
 * ⚙️【推荐执行频率】
 *   建议在 [task_local] 中配置每天早晚各执行一次（如：0 8,20 * * *）。
 * ====================================================================
 */

const timeout = 3000; // 3 秒超时保护机制

function flushDNS() {
    return new Promise((resolve, reject) => {
        if (typeof $configuration !== "undefined" && $configuration.sendMessage) {$configuration.sendMessage({ action: "dns_clear_cache" })
                .then(() => resolve("DNS 缓存已成功清理"))
                .catch((err) => reject(`刷新失败: ${err}`));
        } else {
            reject("当前环境不支持 $configuration.sendMessage API");
        }
    });
}

// 超时兜底逻辑，防止脚本后台卡死挂起
const timer = setTimeout(() => {
    console.log("[DNS Flush] 执行超时，强行结束");
    $done();
}, timeout);

flushDNS()
    .then((msg) => {
        clearTimeout(timer);
        console.log(`[DNS Flush] ${msg}`);
        
        // Quantumult X 规范通知 API：$notify(title, subtitle, message)
        // 如需静默无打扰运行，可直接注释掉下面这行代码：
        $notify("Quantumult X", "网络优化", msg);
        
        $done();
    })
    .catch((err) => {
        clearTimeout(timer);
        console.log(`[DNS Flush] ${err}`);
        $done();
    });
