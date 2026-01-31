# vps-setup
提升 VPS 原版系统开箱使用便捷性设置脚本

脚本支持 Debian 10 -13 和 Ubuntu 20.04 - 24.04

## 功能特点
- 常用软件包自动安装
- 主机名交互配置
- 时区自动配置
- 检查并开启时间同步
- BBR 自动开启
- DNS 自动配置
- ssh 端口和密码配置
- 系统更新和清理

## 一键脚本
```
apt install curl -y && bash <(curl -fsSL https://raw.githubusercontent.com/jet3918/vps-setup/main/install.sh)
```
运行一键脚本后依次配置：
1. 自动检查并安装 sudo wget htop nano常用应用
2. 询问是否设置主机名
3. 自动检测并设置 VPS 所在时区
4. 自动检查并开启时间同步
5. 默认开启 BBR
6. 自动配置 DNS（默认 ipv4 1.1.1.1 8.8.8.8 ; ipv6 2606:4700:4700::1111 2001:4860:4860::8888）
7. 询问是否修改 ssh 端口和密码
8. 系统更新及清理

## 无交互自定义脚本
```
apt install curl -y && curl -o install.sh -fsSL https://raw.githubusercontent.com/jet3918/vps-setup/main/install.sh && chmod +x install.sh && ./install.sh --hostname "hostname" --timezone "Asia/Hong_Kong" --swap "1024" --bbr-optimized --ip-dns "94.140.14.14 1.1.1.1" --ip6-dns "2a10:50c0::ad1:ff 2606:4700:4700::1111" --ssh-port 12345 --ssh-password 'woshimima' --fail2ban 12345 --non-interactive
```
运行无交互自定义脚本后依次配置：
1. 自动检查并安装 sudo wget htop nano常用应用
2. 自动配置自定义主机名
3. 自动配置自定义时区
4. 自动检查并开启时间同步
5. 默认开启 BBR 并根据 VPS 配置智能优化 TCP 网络参数
6. 自动配置自定义 DNS
7. 自动配置自定义 ssh 端口和 ssh 密码
8. 系统更新及清理

## 配合 bin456789 一键 DD 脚本

https://github.com/bin456789/reinstall


一键 DD 脚本

Debian
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh debian 13 --ssh-port 端口 --password 密码
```
Ubuntu
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh ubuntu 24.04 --ssh-port 端口 --password 密码
```
DD脚本的系统版本、 ssh 端口和 password 请自行修改
