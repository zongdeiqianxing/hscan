# -*- coding: utf-8 -*-
import sys,os,re,getopt,time,requests,urllib,queue
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor , as_completed ,wait # 线程池，进程池
import threading
import simplejson
import warnings
from prettytable import PrettyTable

warnings.filterwarnings(action='ignore')
urls_queue = queue.Queue()
tclose = 0
savePath = os.getcwd()
domains =[]
urls = []
dirsearch_urls = []
xray_threading_exists = 0
request_threading_exists = 0
xray_sacned_over = False
row = PrettyTable()
row.field_names = ["status_code", "response_len","url"]
row.border = 0
row.align = 'l'

class url_deal():
	def __init__(self,url):
		self.url = url

	def http_url(self):
		if 'http' not in self.url:
			self.url = 'http://' + self.url
		return self.url

	def domain(self):
		if 'http' not in self.url:
			return self.url
		return urllib.parse.urlparse(self.url).netloc

	def output_url_file(self):
		output_url_file = os.path.join(savePath,self.domain()+'-scaned.url')
		return output_url_file

	def output_subdomain_file(self):
		output_domain_file = os.path.join(savePath,self.domain()+'.sub')
		return	output_domain_file

class scan_deal():
	def __init__(self,url):
		self.url = url
		self.domain = url.domain()
		self.http_url = url.http_url()
		self.now = time.strftime("%Y%m%d%H%M%S", time.localtime(time.time()))
		self.all_tools_output = self.domain + self.now + '-all_tools_output.xlog'
		self.nmap_logfile = '/tmp/' + self.now + '-nmap.log'
		self.nmap_threading_over = 0
		self.jsfinder_logfile ='/tmp/' + self.now + '-jsfinder.log'
		self.jsfinder_threading_over = 0
		self.nikto_logfile = '/tmp/' + self.now + '-nikto.txt'
		self.nikto_threading_over = 0
		self.all_threading_status = [ self.nmap_threading_over,self.jsfinder_threading_over, self.nikto_threading_over]

	def nmap_scan(self):
		print("##nmap Scan")
		print(os.system("nmap -sS -Pn -A -v " + self.domain + ' -oN '+ self.nmap_logfile))
		self.nmap_threading_over = 1
		print('nmap scan ends')

	def jsfiner_scan(self):
		print("##JSfinder Scan")
		print(os.system("python3 ./tools/JSFinder/JSFinder.py -d -u " + self.http_url + ' -ou ' + self.jsfinder_logfile))
		self.jsfinder_threading_over = 1
		print('jsfinder scan ends')

	def nikto_scan(self):
		print('##nikto Scan')
		print(os.system("nikto -h " + self.domain + ' -o ' + self.nikto_logfile))
		self.nikto_threading_over =1
		print('nikto scan ends')

	def judge_all_threading_status(self,output_url_file=''):
		self.all_threading_status = [self.nmap_threading_over, self.jsfinder_threading_over, self.nikto_threading_over]
		print("all_threading_status:",self.all_threading_status)
		if 0 in self.all_threading_status:
			return False
		else :
			all_file = self.nmap_logfile + ' ' + self.nikto_logfile + ' ' + self.jsfinder_logfile
			os.system("cat " + output_url_file + ' ' + all_file + " > " + self.all_tools_output)
			os.system("cp " + self.all_tools_output + ' *.html *.url /mnt')
			os.system("mv " + output_url_file + " /tmp")
			#os.system("mv xray.log /tmp")
			return True

	def check_scan_status(self):
		while(True):
			if self.judge_all_threading_status():
				sys.exit("** end scan **")

def untar():
	def untar():
		if os.path.exists('tools/dirsearch.zip'):
			os.system("for tar in tools/*.zip; do unzip -d tools $tar; done")
			os.system("mv tools/dirsearch.zip tools/dirsearch.zip.bak")
def BruteDomain(Domain):
	untar()
	print("Brute domain: " + Domain)
	#print(os.system("docker run -it --rm -v `pwd`/OneForAll/results/:/OneForAll/results/ -v `pwd`/OneForAll/config/:/OneForAll/config/ oneforall --target " + Domain + " run"))
	print(os.system('python3 tools/OneForAll/oneforall.py --target ' + Domain + ' run'))
	outputFile="tools/OneForAll/results/" + Domain + ".csv"
	if not os.path.exists(outputFile):
		exit("Not found the OneForAll's output file ")
	return outputFile

def crawlergp_request(url):
	global urls
	while tclose==0 or urls_queue.empty() == False:
		if(urls_queue.qsize()==0):
			continue
		print("urls_queue.qsize():",urls_queue.qsize())
		req =urls_queue.get()
		proxies = {
		'http': 'http://127.0.0.1:7777',
		'https': 'http://127.0.0.1:7777',
		}
		try:
			urls0 =req['url']
			headers0 =req['headers']
			method0=req['method']
			data0=req['data']
		except Exception:
			print(type(req))
			urls0 = req
			headers0 = {'User-Agent': 'Mozilla/5.0'}
			method0 = 'GET'
		try:
			# with open(url.output_url_file(),'a+') as f:
			#	  f.write(urls0)
			if urls0 not in urls:
				urls.append(urls0)
			print("requests url :" , urls0)
			if(method0=='GET'):
				a = requests.get(urls0, headers=headers0, proxies=proxies,timeout=30,verify=False)
				row.add_row([a.status_code,str(len(a.content))+'B',urls0])
			elif(method0=='POST'):
				a = requests.post(urls0, headers=headers0,data=data0, proxies=proxies,timeout=30,verify=False)
				row.add_row([a.status_code,str(len(a.content))+'B',urls0])
		except Exception as e:
			print(e)
			continue
	return

def crwalergo_control(url):
	http_url = url.http_url()
	if "http" not in http_url:
		http_url = 'http://'+http_url
	print('crawl:',http_url)
	try:
		cmd = ["./tools/crawlergo", "-c", "/usr/bin/google-chrome","-t", "20","-f","smart","--fuzz-path","--output-mode", "json", http_url]
		rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output, error = rsp.communicate()
	except Exception:
		return
	try:
		result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
	except:
		return
	req_list = result["req_list"]
	#print(http_url)
	print("[crawl ok]")
	try:
		for req in req_list:
			print(req)
			urls_queue.put(req)
	except Exception as e:
		print(e)
		return

	global request_threading_exists
	if request_threading_exists == 0:
		t = threading.Thread(target=crawlergp_request,args=(url,))
		t.start()
		request_threading_exists = 1
	return

def Scan(url):
	global urls
	s = scan_deal(url)
	now = s.now
	http_url = url.http_url()
	domain = url.domain()
	output_url = domain + now + '-scaned.url'
	global tclose

	pool = ProcessPoolExecutor(max_workers=4)
	result=os.popen("nmap -sS -Pn -p 80 " + domain).read()
	#time.sleep(5)
	if re.findall(r'80/tcp\sopen', result):
		crwalergo_control(url)
		#tclose = 1

		while(True):
			if xray_status():
				print("xray_status break")
				break

		try:
			print("##dirsearch Scan")
			logfile = '/tmp/' + now + 'dirsearch.log'
			print(os.system("python3 ./tools/dirsearch/dirsearch.py -e * -x 301,403,404,405,500,501,502,503 -u "+ http_url + ' --simple-report ' + logfile))
			with open(logfile,'r') as f:
				for url in f.readlines():
					if url not in urls:
						urls.append(url)
						urls_queue.put(url)

			global row
			with open(output_url,'w') as f:
				f.write(str(row))
				f.write('\n')
#				 for url in urls:
#					 f.write(url.strip()+'\n')
			row.clear_rows()
			urls = []

			s.nmap_scan()
			os.system("cat {0} >> {1}".format(s.nmap_logfile, output_url))
			s.jsfiner_scan()
			os.system("cat {0} >> {1}".format(s.jsfinder_logfile, output_url))

			# future1 = pool.submit(s.nmap_scan(),)
			# future2 = pool.submit(s.jsfiner_scan(), )
			# future3 = pool.submit(s.nikto_scan(), )
			# future4 = pool.submit(s.judge_all_threading_status)
		except Exception as e:
			print("scan %s"%domain," error:%s"%e)
	else:
		print(domain + "未开放80端口")
		future1 = pool.submit(s.nmap_scan(),)
		os.system("cp {logfile} /root/{domain}.nmap".format(logfile=s.nmap_logfile,domain=domain))


	#future = pool.submit(s.check_scan_status(),)


def fileScan(filename):
	with open(filename,'r') as f:
		for line in f.readlines():
			subdomainName=re.search('[\w(\-)\.\w]{6,}',line).group(0)
			if '.' not in subdomainName:
				continue
			if subdomainName not in domains:
				domains.append(subdomainName)
				urlScan(subdomainName,url_scan=False)
	print("scaned over")
	os.system("mv xray.log /tmp")

def urlScan(url,url_scan=True):
	untar()
	#run xray
	global	xray_threading_exists
	url = url_deal(url)
	print('domain',url.domain())
	now = time.strftime("%Y%m%d%H%M%S", time.localtime(time.time()))
	outputfile= os.path.join(savePath,url.domain()+now+'-xrayScan.html')
	if xray_threading_exists == 0 :
		xray_threading_exists = 1
		t = threading.Thread(target=xray_run,args=(outputfile,))
		t.start()
	Scan(url)
	print(url.domain() + " scaned over")
	if url_scan:
		os.system("mv xray.log /tmp")
	

def xray_run(output_file):
	print(os.system('./tools/xray_linux_amd64 webscan --listen 127.0.0.1:7777 --html-output ' + output_file + " | tee -a xray.log"))

def xray_status():
	global xray_sacned_over
	cmd = "wc xray.log | awk '{print $1}'"
	rows0 = os.popen(cmd).read()
	time.sleep(5)
	rows1 = os.popen(cmd).read()
	cmd	 = "tail -n 10 xray.log"
	s = os.popen(cmd).read()
	if rows0 == rows1 and "All pending requests have been scanned" in s:
		print("rows:", rows0, rows1)
		return True
	else:
		return False

if __name__ == '__main__':
	Usage='''
Usage:
	python3 recon.py -u url 
	python3 recon.py -f filename		#-f参数使用时，为每行正则匹配域名，已测试的可适配OneforAll、subDoaminBrute的outut文件；手写域名进入也可；
	python3 recon.py -d domain			#-d参数使用时，输入主域名，自动使用OneForAll工具查找所有子域名，后自动使用Scan模块扫描。
'''

	try:
		opts, args = getopt.getopt(sys.argv[1:],"hu:f:d:",["url=","file=","domain="])
		for opt,arg in opts:
			if opt == '-h':
				print(Usage)
			if opt == '-u':
				urlScan(arg)
			if opt == '-f':
				fileScan(arg)
			if opt == '-d':
				OneForAll_File=BruteDomain(arg)
				fileScan(OneForAll_File)
	except getopt.GetoptError:
		print(Usage)
	except KeyboardInterrupt:
		exit("ctrl+c exit")

''
