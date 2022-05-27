# Nginx + Flask搭建自定义登录认证（--nginx-auth-request-module 模块） 

## 前言

内部服务都部署在阿里云环境下，采传统方法使用basic认证，除了用户管理起来麻烦之外，还有对内部人员操作不友好的情况，故通过nginx-auth-request-module来实现认证转移。

## Nginx 的 auth_request 模块

auth_request 大抵就是在你访问 Nginx 中受 auth_reuqest 保护的路径时，去请求一个特定的服务。根据这个服务返回的状态码，auth_request 模块再进行下一步的动作，允许访问或者重定向跳走什么的。因此我们可以在上面去定制我们所有个性化的需求。

## nginx安装
本测试环境，以centos.7.9

```shell
yum install epel-release -y
yum install nginx
```

nginx -V 确认是否带有auth_request模块

```shell
nginx -V
```

**Nginx 认证**

    主要利用nginx-auth-request-module进行鉴权

1. auth_request对应的路由返回401 or 403时，会拦截请求直接nginx返回前台401 or 403信息；
2. auth_request对应的路由返回2xx状态码时，不会拦截请求，而是构建一个subrequest请求再去请求真实受保护资源的接口；

- 生成密码的方式

```python
>>> from werkzeug.security import generate_password_hash
>>> generate_password_hash("12345678")
'pbkdf2:sha256:150000$8J65mjTc$db116dd4d5de7eff899d126bd57b4f73910afb1e57982a9ded6878c547b584c5'
```