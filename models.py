from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    """
    登录表单类
    """
    username = StringField(label='用户名', validators=[DataRequired("用户名不能为空"), Length(max=10, min=3, message="用户名长度必须大于3且小于8")])
    password = PasswordField(label='请输入密码', validators=[DataRequired("密码不能为空"), Length(max=10, min=6, message="密码长度必须大于6且小于10")])
    captcha = StringField(label='验证码', validators=[DataRequired("验证码不能为空"), Length(max=4, min=4, message="验证码输入错误")])
    submit = SubmitField(label='立即登录')
