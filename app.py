import json
import os.path

import requests
from flask import Flask, request, session, make_response, redirect, render_template, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user
from werkzeug.security import check_password_hash
from UserService import UserService

from mycaptcha import Captcha

app = Flask(__name__)

app.debug = True

login_manager = LoginManager(app)  # pip install flask_login
login_manager.session_protection = "strong"  # 保护session和cookie

res = {'code': 200, 'msg': '成功', 'data': {}}

# 存放用户名和密码的json文件
PROFILE_PATH = os.path.dirname(os.path.abspath(__file__))
PROFILE_FILE = os.path.join(PROFILE_PATH, "profiles.json")

CONFIG_PATH = os.path.join(PROFILE_PATH, "config/base_setting.py")
# 配置文件分为 本地和测试两个
LOCAL_CONFIG = os.path.join(PROFILE_PATH, "config/local_setting.py")
TEST_CONFIG = os.path.join(PROFILE_PATH, "config/test_setting.py")
# print(LOCAL_CONFIG, TEST_CONFIG)
TYPE_CONFIG = LOCAL_CONFIG if os.path.exists(LOCAL_CONFIG) else TEST_CONFIG

if os.path.exists(CONFIG_PATH):
    app.config.from_pyfile(CONFIG_PATH)

if os.path.exists(TYPE_CONFIG):
    app.config.from_pyfile(TYPE_CONFIG)


# 用户密码加密认证
class User(UserMixin):
    def __init__(self, username):
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

    def get_id(self):
        return self.username

users = {}


@login_manager.user_loader
def load_user(user_id):
    # 从文件中获取密码
    try:
        with open(PROFILE_FILE) as f:
            user_profiles = json.load(f)
            user_info = user_profiles['dataObjects'][0]

        if user_info is not None:
            return user_info[0]
    except:
        print("get password error!")
    print("user_id", user_id)
    print("user_id", user_info)
    if id in users:
        return users[id]
    return None


# 测试地址
@app.route('/ip')
def ip():
    return request.remote_addr


@app.route('/')
def index():
    cookies = request.cookies
    auth_cookie = cookies[app.config["AUTH_COOKIE_NAME"]] if app.config["AUTH_COOKIE_NAME"] in cookies else None

    if auth_cookie:
        auth_info = auth_cookie.split("#")
        user_info = User(auth_info[1])
        pwd = f"{UserService.geneAuthCode(auth_info[1], user_info.get_password_hash())}"
        if auth_info[0] != pwd:
            return redirect(url_for('login'))
        resp = make_response('欢迎你', auth_info[1])
    return resp, 200


@app.route('/captcha', methods=['GET', 'POST'])
def get_captcha():
    mc = Captcha()
    session['captcha'] = mc.code
    print(session['captcha'])
    # print(mc.base64_png)
    return mc.base64_png


@app.route("/auth")
def auth():
    # url = request.cookies.get('')
    cookies = request.cookies
    auth_cookie = cookies[app.config["AUTH_COOKIE_NAME"]] if app.config["AUTH_COOKIE_NAME"] in cookies else None

    if auth_cookie is None:
        app.logger.info(f'auth cookie不存在 {auth_cookie}')
        resp = make_response('登录信息过期或错误，请重新登录')
        return resp, 401

    auth_info = auth_cookie.split("#")
    user_info = User(auth_info[1])
    pwd = f"{UserService.geneAuthCode(auth_info[1], user_info.get_password_hash())}"
    if auth_info[0] != pwd:
        app.logger.info('auth cookie不符合，请登录')
        resp = make_response('登录信息过期或错误，请重新登录')
        return resp, 401

    res['msg'] = 'success'

    return res


@app.route('/login', methods=['GET', 'POST'])
def login():
    print("------------------")
    SITE_NAME = ''

    if 'ORIGIN_SITE_NAME' in request.cookies:
        SITE_NAME = request.cookies.get('ORIGIN_SITE_NAME')

    URL = ''
    if 'ORIGIN_URL' in request.cookies:
        URL = request.cookies.get('ORIGIN_URL')

    print("URL: ", URL)

    print("current_user.is_anonymous: ", current_user.is_anonymous)
    print("current_user is_authenticated: ", current_user.is_authenticated)


    cookies = request.cookies
    auth_cookie = cookies[app.config["AUTH_COOKIE_NAME"]] if app.config["AUTH_COOKIE_NAME"] in cookies else None
    if auth_cookie:
        auth_info = auth_cookie.split("#")

        print(auth_info)
        user_info = User(auth_info[1])
        pwd = f"{UserService.geneAuthCode(auth_info[1], user_info.get_password_hash())}"
        print(pwd)
        if auth_info[0] == pwd:
            resp = make_response('<meta http-equiv="refresh" content="3; url=' + URL + '" />你已经登录过！不要重复登录！')
            return resp, 200

    if 'captcha' not in session:
        mc = Captcha()
        session['captcha'] = mc.code

    if request.method == 'GET':
        mc = Captcha()
        session['captcha'] = mc.code
        app.logger.info(f"get new captcha: {mc.code}")

        return render_template('login.html', img_captcha=mc.base64_png, site_name=SITE_NAME, url=URL)

    req = request.values
    username = req['username'] if 'username' in req else ''
    password = req['password'] if 'password' in req else ''
    captcha = req['captcha'].upper() if 'captcha' in req else ''
    if username is None or len(username) < 1:
        res['code'] = -1
        res['msg'] = "请输入正确的用户名和登录密码~~"
        return jsonify(res)

    if password is None or len(password) < 6:
        res['code'] = -1
        res['msg'] = "请输入正确的用户名和登录密码~~"
        return jsonify(res)

    app.logger.warning(f"验证码: {session['captcha']} 输入: {captcha}")
    if not captcha == session['captcha']:
        mc = Captcha()
        session['captcha'] = mc.code
        print("new captcha: " + captcha)
        print("new session captcha: " + session['captcha'])

        res['code'] = -1
        res['msg'] = "请输入正确的验证码~~"
        res['data'] = {'captcha': mc.base64_png}
        return jsonify(res)

    user = User(username)
    if not user.verify_password(password):
        app.logger.info("登录失败，请重试! ")
        mc = Captcha()
        session['captcha'] = mc.code
        res['msg'] = "用户不存在，请重试!"
        res['code'] = -1
        res['data'] = {'captcha': mc.base64_png}
        return jsonify(res)

    app.logger.info(f"登录密码: {password}")
    res['mgs'] = 'you login!'
    response = make_response(res)
    cookies_str = f"{UserService.geneAuthCode(username, user.get_password_hash())}#{username}"
    print(cookies_str)
    response.set_cookie(app.config["AUTH_COOKIE_NAME"], cookies_str)
    app.logger.info(f'username: {username} login success!')

    if URL:
        app.logger.info('重定向到的URL: ' + URL)
        # return redirect(URL)
        res['data'] = {'ORIGIN_URL': URL}
        return jsonify(res)

    return response


@app.route('/logout')
def logout():
    flash('注销成功！', 'success')
    url = request.cookies.get('ORIGIN_URL')

    return redirect(url)


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
        app.config['WEB_HOOK_URL'],
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
