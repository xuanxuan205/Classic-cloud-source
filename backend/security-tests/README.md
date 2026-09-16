# security-tests · Python 载荷回归矩阵

## 目的

`ironwall_regression_test.py` 对目标站点执行黑盒载荷矩阵：攻击载荷必须被引擎拦截
（403/406/418/444/503/429），一旦任何攻击载荷返回 200 即判定漏网并退出非 0。
良性对照保持 200，默认只告警不判失败（防止测试者 IP 被封后误伤门禁）。

## 运行方式

```powershell
# 本地（默认打 https://example.com，可用环境变量覆盖目标）
python security-tests\ironwall_regression_test.py --list-only
python security-tests\ironwall_regression_test.py --include-post --timeout 15

# 发布门禁显式开启（Java 全量回归 + Python 矩阵，GAP=0 才放行）
powershell -ExecutionPolicy Bypass -File deploy\security-gate.ps1 -RunPython

# 供应链扫描（尽力而为：缺插件/无网络只提示、不红）
powershell -ExecutionPolicy Bypass -File deploy\security-gate.ps1 -RunSupplyChain
```

## 注意事项

- 默认目标 `https://example.com`，可用环境变量 `IRONWALL_BASE_URL` 覆盖（自测/预发）。
- 脚本发送真实攻击特征，引擎会记录并按设计封禁来源 IP；**不要用管理站点常用的 IP 运行**，
  建议使用一次性出口地址，并在测试后到安全面板解封。
- `--include-post` 才会发送 multipart / JSON POST 探测。
- 不要提交真实密钥/管理员账号到仓库；如需鉴权测试请读环境变量。
