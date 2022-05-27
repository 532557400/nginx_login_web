import base64
import random
import string
from io import BytesIO
from flask import make_response
from captcha.image import ImageCaptcha, random_color

CAPTCHA_LEN = 4


# string.ascii_letters   包含所有英文字母
# string.digits          包含0-9的所有数字


class Captcha:
    code = None

    def __init__(self):
        self.ca = string.digits + string.ascii_letters  # 拼接字符串
        self.base64_png = self.create()

    def create(self):
        self.code = ''.join(random.sample(self.ca, CAPTCHA_LEN))  # 随机字符，字符个数
        # now = time.time()
        #
        # path = './static/captcha/'
        # if not os.path.exists(path):
        #     os.makedirs(path)
        # self.img = path + str(now) + '.png'
        img = ImageCaptcha(width=130, height=40, font_sizes=(30, 35, 28))  # 实例化ImageCaptcha类
        # 这是ImageCaptcha自带的初始化内容width=160, height=60, fonts=None, font_sizes=None，可以自己设置

        RGB = (38, 38, 0)  # 字体色
        bgc = (255, 255, 255)  # 背景色
        color = random_color(50, 180)  # 生成随机颜色
        print(color)
        image = img.create_captcha_image(self.code, RGB, bgc)
        img.create_noise_dots(image=image, color=color, width=10, number=10)
        img.create_noise_curve(image=image, color=RGB)
        buffer = BytesIO()
        image.save(buffer, "PNG")  # 将Image对象转为二进制存入buffer，因BytesIO()是内存中操作，所以实际是存入内存
        buf_bytes = buffer.getvalue()  # 从内存中取出bytes类型的图片
        # response = make_response(buf_bytes)
        # response.headers['Content-Type'] = 'image/png'  # 设置请求头， 文件格式与前面save时一致

        base64_data = 'data:image/png;base64,' + str(base64.b64encode(buf_bytes), 'utf-8')  #
        return base64_data
        # image.save(self.img)
        # image.write(self.code, self.img)
