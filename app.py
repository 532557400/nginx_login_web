import json
import os.path
from datetime import timedelta

import requests
from flask import Flask, request, session, make_response, redirect, render_template, url_for, flash
from flask_login import LoginManager, UserMixin, current_user, logout_user
from werkzeug.security import check_password_hash

from mycaptcha import Captcha

app = Flask(__name__)

# session
app.config["SECRET_KEY"] = "123456"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.secret_key = '123456'

app.debug = True

login_manager = LoginManager(app)  # pip install flask_login
login_manager.session_protection = "123456"  # 保护session和cookie

res = {'code': 200, 'msg': '成功', 'data': {}}

# 存放用户名和密码的json文件
PROFILE_PATH = os.path.dirname(os.path.abspath(__file__))
PROFILE_FILE = os.path.join(PROFILE_PATH, "profiles.json")


# 用户密码加密认证
class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password_hash = self.get_password_hash()

    def verify_password(self, password):
        if self.password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)

    def get_password_hash(self):
        # 从文件中获取密码
        try:
            with open(PROFILE_FILE) as f:
                user_profiles = json.load(f)
                user_info = user_profiles.get(self.username, None)

            if user_info is not None:
                return user_info[0]
        except:
            print("get password error!")


users = {}


@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User.get(user_id)
    return None


# 测试地址
@app.route('/')
def index():
    if not current_user or current_user.is_anonymous:
        return redirect(url_for('login'))
    resp = make_response('欢迎你', current_user.displayName)
    return resp, 200


@app.route('/ip')
def ip():
    return request.remote_addr


@app.route('/captcha', methods=['GET', 'POST'])
def get_captcha():
    mc = Captcha()
    session['captcha'] = mc.code
    print(session['captcha'])
    #print(mc.base64_png)
    return mc.base64_png


@app.route('/login', methods=['GET', 'POST'])
def login():


    sitename = ''
    url = ''
    print("NSREDIRECTSITENAME", request.cookies.get('NSREDIRECTSITENAME'))
    print("NSREDIRECT", request.cookies.get('NSREDIRECT'))

    if current_user and not current_user.is_anonymous:
        resp = make_response('<meta http-equiv="refresh" content="3; url=' + '' + '" />你已经登陆过！不要重复登陆！')
        return resp, 200

    if request.method == 'GET':
        mc = Captcha()
        session['captcha'] = mc.code

        print(mc.code)
        return render_template('login.html', img_captcha=mc.base64_png, sitename=sitename, url=url)

    if request.method == 'POST':
        mc = Captcha()

        print("------------------")
        print(request.form)
        print(request.form['captcha'].upper())
        print(session['captcha'].upper())
        if not request.form['captcha'].upper() == session['captcha'].upper():
            print("no")
        #if not request.form.get('captcha').upper() == session['captcha'].upper():
            print('request: ' + request.form.get('captcha').upper())
            print('session: ' + session['captcha'].upper())
            flash('验证码错误，请重新输入', 'danger')


            session['captcha'] = mc.code
            return render_template('login.html', img_captcha=mc.base64_png, sitename=sitename, url=url)

        username = request.form.get('username') if 'username' in request.form else ''
        password = request.form.get('password') if 'password' in request.form else ''

        user = User(username, password)
        if user.verify_password(password):
            response = make_response(redirect('/'))
            response.set_cookie('username', username)
            app.logger.info('username ' + username + 'login!')
            return response
        else:
            flash('登陆失败，请重试！', 'danger')
            app.logger.warning(request.form['username'] + 'login error')
            session['captcha'] = mc.code
            return render_template('login.html', img_captcha=mc.base64_png, sitename=sitename, url=url)


@app.route('/logout')
def logout():
    flash('注销成功！', 'success')
    logout_user()

    return redirect('/')


# 获取服务状态
@app.route('/dts/item/<name>/<status>', methods=["GET"])
def get_item_status(name, status):
    print(name, status)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        'Content-Type': 'application/json'
    }  # 设置headers

    data = {
        "msgtype": "text",
        "text": {
            "content": "hello world"
        }
    }

    response = requests.post(
        'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=7f56ccd4-f297-4ded-85ab-0d7385f81c1c',
        data=json.dumps(data), headers=headers)
    # print(type(response.json()))
    # print(type(response.status_code))
    # 判断状态代码
    if response.status_code != 200:
        res['code'] = response.status_code
        return json.dumps(res, sort_keys=False, ensure_ascii=False)

    response = response.json()
    # res['code'] = response.status_code
    res['msg'] = "执行成功!"
    res['data'] = response
    return json.dumps(res, sort_keys=False, ensure_ascii=False, indent=2)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
