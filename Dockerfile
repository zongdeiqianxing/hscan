FROM ubuntu:latest


RUN apt update
RUN apt install -y python3 python3-pip wget gnupg nmap nikto zip
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub  | apt-key add -
RUN sh -c 'echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
RUN apt update
ENV TIME_ZONE Asiz/Shanghai
ENV DEBIAN_FRONTEND=noninteractive
RUN apt install -y tzdata
RUN ln -fs /usr/share/zoneinfo/Asiz/Shanghai /etc/localtime
RUN dpkg-reconfigure -f noninteractive tzdata
RUN apt-get install -y google-chrome-stable 
RUN pip3 install simplejson requests bs4 prettytable

ADD . /root/
WORKDIR /root/
RUN if [ ! -f "tools/install.lock" ];then for tar in tools/*.zip; do unzip -d tools $tar; done fi
RUN touch tools/install.lock
RUN pip3 install -r ./tools/OneForAll/requirements.txt
ENTRYPOINT ["python3","recon.py"]
