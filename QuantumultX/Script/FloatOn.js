// 悬浮精灵 (FloatOn) 去弹窗广告
// 修改 configs 接口，强制关闭主弹窗
let body = $response.body;
if (body) {
  try {
    let obj = JSON.parse(body);
    if (obj.data) {
      obj.data.mainPop_open = 0;   // 关闭弹窗
      obj.data.noAds = 1;          // 标记无广告
      if (obj.data.mainPop) {
        obj.data.mainPop = {};     // 清空弹窗内容
      }
    }
    body = JSON.stringify(obj);
  } catch (e) {
    console.log("悬浮精灵解析失败: " + e);
  }
}
$done({ body });