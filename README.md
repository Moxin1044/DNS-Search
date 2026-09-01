# DNS-Search

使用 Go 编写的 DNS 主域名查询工具。工具会查询常见 DNS 记录，并尝试向域名权威 DNS 服务器发起 AXFR 区域传送；如果 AXFR 未开放，则探测一组常见子域名。AXFR 未开放时，DNS 协议本身无法保证枚举出域名下的“所有”记录。

## 构建

```powershell
go mod tidy
go build -o dns-search.exe .
```

## 使用

```powershell
./dns-search.exe -d domain.com
```

使用自定义 DNS 服务器。`-dns` 可以重复指定，也可以使用逗号分隔；未指定时使用内置默认列表：

```powershell
./dns-search.exe -d domain.com -dns 223.5.5.5 -dns 114.114.114.114
./dns-search.exe -d domain.com -dns 8.8.8.8,1.1.1.1
./dns-search.exe -d domain.com -dns 192.168.1.1:53
```

`-dns` 同样适用于 `--webui` 模式，Web UI 发起的查询会使用启动参数指定的 DNS 服务器。

不传 `-d` 时进入交互式输入：

```powershell
./dns-search.exe
```

启动 Web UI：

```powershell
./dns-search.exe --webui
```

默认访问 `http://127.0.0.1:8080`，也可以通过 `--addr 0.0.0.0:8080` 修改监听地址。

## 查询范围

默认查询 `A`、`AAAA`、`CNAME`、`MX`、`NS`、`TXT`、`SRV`、`CAA`、`SOA`，并尝试 AXFR。请仅对自己拥有或明确获授权的域名进行测试。

默认按以下顺序使用公共 DNS 解析服务，当前面的服务不可用或拒绝查询时自动切换：

1. `223.5.5.5:53`（阿里公共 DNS）
2. `114.114.114.114:53`（114DNS）
3. `1.1.1.1:53`（Cloudflare DNS）
4. `8.8.8.8:53`（Google Public DNS）

## 自动发布

推送版本标签（例如 `v1.0.0`）后，GitHub Actions 会自动构建 Windows、Linux 和 macOS 的 amd64/arm64 制品，并创建公开 GitHub Release。
