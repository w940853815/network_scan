#!/usr/bin/env python
# -*- coding: utf_8 -*-
# Author:ruidong.wang
import multiprocessing
from IPy import IP
import threading
import nmap
import time
import sys
import subprocess
from xml.dom import minidom


def usage():
	print
	'The script requires root privileges!'
	print
	'example:python scan.py 192.168.0.1/24'


# 生成xml文件的模板函数
def addResult(newresult):
	global doc
	global scan_result

	ip = doc.createElement("ip")
	ip.setAttribute("address", newresult["address"])

	osclass = doc.createElement("osclass")
	osclass.appendChild(doc.createTextNode(newresult["osclass"]))
	ip.appendChild(osclass)

	port = doc.createElement("port")

	tcp = doc.createElement("tcp")
	tcp.appendChild(doc.createTextNode(newresult["tcp"]))
	port.appendChild(tcp)

	udp = doc.createElement("udp")
	udp.appendChild(doc.createTextNode(newresult["udp"]))
	port.appendChild(udp)

	ip.appendChild(port)
	scan_result.appendChild(ip)


# 扫描函数，调用nmap库
def ip_scan(ip):
	nm = nmap.PortScanner()
	# 这里调用系统ping命令来判断主机存活
	p = subprocess.Popen("ping -n 1 " + ip, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
	                     shell=True)
	out = p.stdout.read()
	# 如过没有100%丢包则主机存活，对是否丢包的判断是抓取系统回显内容，测试用的是‘MAC OS X’系统，抓取内容为‘100.0% packet loss’
	if u'丢失 = 0' in out:
		try:
			# 调用nmap扫描主机操作系统，同时进行SYN扫描和UDP扫描探测开放的端口
			res = nm.scan(ip, arguments='-O -sS -sU -F')
			print (res['scan'])
		except Exception as e:
			print e


# 循环，遍历未扫描的IP
def loop():
	global mutex
	global ipx

	while 1:
		# 线程锁，扫描一个IP就将IPX列表中的该IP移除
		mutex.acquire()
		# 如果列表中没有IP，则跳出循环结束该线程
		if len(ipx) <= 0:
			mutex.release()
			break
		ip = ipx[0]
		ipx.remove(ipx[0])
		mutex.release()
		# 调用扫描函数
		ip_scan(str(ip))


# 创建线程的函数，默认创建40个
def creat_threads():
	threads = []
	for i in range(40):
		threads.append(threading.Thread(target=loop, ))
	for t in threads:
		t.start()
	for t in threads:
		t.join()


def start():
	# mutex:线程锁
	global mutex
	# ipx:存储要扫描的IP地址段列表
	global ipx
	# doc:xml文档对象
	global doc
	# scan_result:xml文档的根元素
	global scan_result

	if '-h' == sys.argv[1]:
		usage()
		exit()
	else:
		# 获取命令行输入的要扫描的IP段
		ip = sys.argv[1]
		# xml文档一些对象的初始化
		doc = minidom.Document()
		doc.appendChild(doc.createComment("scan_result xml."))
		scan_result = doc.createElement("scan_result")
		doc.appendChild(scan_result)

		# 初始化参数
		ipx = []
		nm = nmap.PortScanner()
		mutex = threading.Lock()

		# 调用IPy模块的IP函数，将IP地址段的每个IP存入列表
		ipp = IP(ip, make_net=True)
		for x in ipp:
			ipx.append(x)
		# 去掉首尾代表子网和全部主机的IP
		ipx = ipx[1:-1]

		print("please wait...")
		# 计算时间
		time_start = time.time()
		print time_start
		# 创建线程
		creat_threads()

		time_end = time.time()
		t = time_end - time_start
		print t
		'*' * 48
		print
		'\nTime:' + str(t) + 's'
		print
		'Scan results have been saved to scan_result.xml.\n'
		print
		'*' * 48

		# xml文件操作
		f = file("scan_result.xml", "w")
		f.write(doc.toprettyxml(indent="\t", newl="\n", encoding="utf-8"))
		f.close()

def worker_1(ip_list1):
	time_start = time.time()
	for ip in ip_list1:
		ip_scan(str(ip))
	time_end = time.time()
	t = time_end - time_start
	print 'worker1'+str(t)

def worker_2(ip_list2):
	time_start = time.time()
	for ip in ip_list2:
		ip_scan(str(ip))
	time_end = time.time()
	t = time_end - time_start
	print 'worker2' + str(t)

def worker_3(ip_list3):
	time_start = time.time()
	for ip in ip_list3:
		ip_scan(str(ip))
	time_end = time.time()
	t = time_end - time_start
	print 'worker3' + str(t)

def worker_4(ip_list4):
	time_start = time.time()
	for ip in ip_list4:
		ip_scan(str(ip))
	time_end = time.time()
	t = time_end - time_start
	print 'worker4' + str(t)

if __name__ == '__main__':
	ip = sys.argv[1]
	ipp = IP(ip, make_net=True)
	ipx = []
	# 调用IPy模块的IP函数，将IP地址段的每个IP存入列表
	ipp = IP(ip, make_net=True)
	for x in ipp:
		ipx.append(x)
	# 去掉首尾代表子网和全部主机的IP
	ipx = ipx[1:-1]
	ip_list1=ipx[0:len(ipx)/4]
	ip_list2 = ipx[len(ipx) / 4:len(ipx)/2]
	ip_list3 = ipx[len(ipx)/2:len(ipx)/4*3]
	ip_list4 = ipx[len(ipx)/4*3:len(ipx)]
	p1 = multiprocessing.Process(target=worker_1, args=(ip_list1,))
	p2 = multiprocessing.Process(target=worker_2, args=(ip_list2,))
	p3 = multiprocessing.Process(target=worker_3, args=(ip_list3,))
	p4 = multiprocessing.Process(target=worker_4, args=(ip_list4,))

	p1.start()
	p2.start()
	p3.start()
	p4.start()