FROM ubuntu:20.04

ENV TZ=Asia/Shanghai
ENV LANG C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

ADD . /root
WORKDIR /root/

RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list \
&& sed -i s/security.ubuntu.com/mirrors.aliyun.com/g /etc/apt/sources.list \
&& apt-get clean \
&& apt update \ 
&& ln -sf /usr/share/zoneinfo/$TZ /etc/localtime \
&& echo $TZ > /etc/timezone \
&& apt install -y python3 python3-pip wget gnupg nmap nikto zip tzdata \
&& wget -q -O - https://dl.google.com/linux/linux_signing_key.pub  | apt-key add - \
&& echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
&& apt update \
&& apt install -y google-chrome-stable \
&& pip3 install simplejson requests bs4 prettytable \
&& /bin/bash -c 'if [ ! -f "tools/install.lock" ];then for zip in tools/*.zip; do unzip -d tools $zip; done; touch tools/install.lock; fi' \
&& pip3 install -r ./tools/OneForAll/requirements.txt

ENTRYPOINT ["python3","recon.py"]
