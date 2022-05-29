import base64
import hashlib


class UserService():
    @staticmethod
    def genePwd(pwd, salt):
        m = hashlib.md5()
        st = f'{base64.encodebytes(pwd.encode("utf-8"))}-{salt}'
        m.update(st.encode("utf-8"))
        return m.hexdigest()

    # 增加此静态加密算法
    @staticmethod
    def geneAuthCode(login_name, login_pwd):
        m = hashlib.md5()
        st = f"{login_name}-{login_pwd}"
        m.update(st.encode("utf-8"))
        return m.hexdigest()