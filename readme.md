# AnyTLS

一个试图缓解 嵌套的TLS握手指纹(TLS in TLS) 问题的代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置

## 协议与设计

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

[URI 格式](./docs/uri_scheme.md)

## 示例项目

> 📌 **项目定位**：本项目是 AnyTLS 协议的**参考实现**，核心目标是**演示协议细节、交互流程与边界场景**，而非提供功能完备的生产级客户端。日常使用推荐 [第三方兼容软件](#第三方兼容软件)。

> ⚠️ 示例服务器和客户端默认采用不安全的配置，该配置假设您不会遭遇 TLS 中间人攻击；否则，您的通信内容可能会被中间人截获。

### 示例服务器

```
./anytls-server -l 0.0.0.0:8443 -p /path/to/users.json
```

`0.0.0.0:8443` 为服务器监听的地址和端口。`-p` 参数为用户 JSON 文件路径，格式为 `{"users":{"user1":"password1","user2":"password2"}}`。进程收到 `SIGHUP` 后会从同一路径重新加载该文件，认证成功后会记录连接对应的用户名。

### 示例客户端

```
./anytls-client -c /path/to/config.yml
```

配置文件格式参见 [`examples/config.yml`](./examples/config.yml)。`clients` 列表中的每一项都会启动一个 Socks5/HTTP 代理监听器，理论上支持 TCP 和 UDP（通过 udp over tcp 传输）。

```
clients:
  - listen: 127.0.0.1:1080
    server: 服务器ip:端口
    password: 密码
```

## 第三方兼容软件

### sing-box

https://github.com/SagerNet/sing-box

它包含了 anytls 协议的服务器和客户端。

### mihomo

https://github.com/MetaCubeX/mihomo

它包含了 anytls 协议的服务器和客户端。

### iOS 独立客户端实现

`Shadowrocket` 2.2.65+ 实现了 anytls 协议的客户端。

`Stash` `Loon` 等客户端已跟进适配。

这些客户端的具体实现细节与协议规范的契合度由各自维护团队负责，其细节处理路径与边界场景应对可能因版本而异，本项目未作验证。
