# 项目基于的python版本
FROM python:alpine3.15

# 把项目 添加到code文件夹 (code无需创建)
ADD ../flaskBazifenxi_he/static /opt/static
ADD ../flaskBazifenxi_he/templates /opt/templates
COPY ../flaskBazifenxi_he/app.py requirements.txt conf_data.py character.py uwsgi.ini /opt/

# 把code设置为工作目录
WORKDIR /opt/

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

RUN mkdir /opt/logs/

RUN apk add gcc

# 导入(安装)项目依赖包
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && pip3 install uwsgi  -i http://pypi.douban.com/simple --trusted-host pypi.douban.com \
    && ln -s  /usr/local/python3/bin/uwsgi /usr/bin/uwsgi

# 端口5000 (可删除)
EXPOSE 5000

# 容器启动后要执行的命令 -> 启动uWSGI服务器
# CMD ["python3", "app.py"]
# CMD ["uwsgi", "--ini", "wsgi.ini"]
ENTRYPOINT uwsgi --ini /app/uwsgi.ini