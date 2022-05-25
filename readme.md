
- 生成密码的方式

```python
>>> from werkzeug.security import generate_password_hash
>>> generate_password_hash("12345678")
'pbkdf2:sha256:150000$8J65mjTc$db116dd4d5de7eff899d126bd57b4f73910afb1e57982a9ded6878c547b584c5'
```