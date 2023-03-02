"""
_*_ coding: utf-8 _*_
@Author : GGStudy_DDUp
@File : IP-PortScan.py
"""
import argparse
import queue
import threading
import time
import ipaddress
import subprocess
import socket
from multiprocessing import Process


def ping(ping_ip):
    rc = subprocess.call(
        'ping -n 1 %s' % ping_ip,
        shell=True,
        stdout=subprocess.DEVNULL
    )  # 定义ping命令的变量，返回值0:正常，返回值1：ping不通
    if rc:
        pass
    else:
        print('{}\t\tUp'.format(ping_ip))  # 当re=0，表示可以ping通，打印up


class Scan:
    def __init__(self, target):
        self.target = target

    def live(self):
        global p, l_i
        if self.target.i is not None and self.target.f is None:
            l_i = self.partition()
        elif self.target.f is not None and self.target.i is None:
            l_i = self.file()
        else:
            exit()
        thread = 1
        for i in l_i:
            p = Process(target=ping, args=(i,))
            p.start()
            if thread != int(self.target.t):
                thread = thread + 1
                continue
            p.join()
            thread = 1
        p.join()

    def port(self):
        global l_i
        q = queue.Queue()
        if self.target.i is not None and self.target.f is None:
            l_i = self.partition()
        elif self.target.f is not None and self.target.i is None:
            l_i = self.file()
        else:
            exit()
        for o_i in l_i:
            for i in range(1, 65536):
                q.put(i)
            threads = [PortScanThread(o_i, q) for _ in range(int(self.target.t))]
            for i in range(int(self.target.t)):
                threads[i].start()
            for i in range(int(self.target.t)):
                threads[i].join()
            continue

    def all(self):
        self.live()
        self.port()

    def file(self):
        f_i = []
        with open(self.target.f, 'r') as f:
            while True:
                x = f.readline().strip()
                if x:
                    f_i.append(x)
                else:
                    break
        return f_i

    def partition(self):
        global t0, t1
        t_tem = []
        # 对输入数据切割‘，’，形成target_group组
        target_group = self.target.i.split(',')
        for t_o in target_group:
            # 对输入数据切割‘-’，形成t_o组
            t_t = t_o.split('-')
            # 判断是否包含‘-’
            if len(t_t) > 1:
                try:
                    t0 = ipaddress.ip_address(t_t[0].strip())
                    t1 = ipaddress.ip_address(t_t[1].strip())
                except ValueError as v:
                    print(v)
                    exit()
                # 对输入范围化为单独IP
                while t0 != t1 + 1:
                    t_tem.append(str(t0))
                    t0 = t0 + 1
            else:
                try:
                    net = ipaddress.ip_network(t_o.strip())
                    # 直接读网段IP
                    for i in net:
                        t_tem.append(str(i))
                except Exception as e:
                    t_tem.append(str(t_o.strip()))
        return t_tem


class PortScanThread(threading.Thread):
    def __init__(self, t_ip, t_port):
        threading.Thread.__init__(self)
        self.t_ip = t_ip
        self.t_port = t_port

    def run(self) -> None:
        while not self.t_port.empty():
            T = self.t_port.get()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((self.t_ip, T))
                s.settimeout(1)
                print("{}:{}\tOn".format(self.t_ip, T))
            except:
                pass
            finally:
                s.close()


class Dispatch:
    def __init__(self, target):
        self.target = target

    def main(self):
        # try:
        if self.target.m == 'live':
            Scan(self.target).live()
        elif self.target.m == 'port':
            Scan(self.target).port()
        elif self.target.m == 'all':
            Scan(self.target).all()
        # except Exception as e:
        #     print(e)


if __name__ == '__main__':
    banner = '''
 ___ ____       ____            _   ____
|_ _|  _ \     |  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __
 | || |_) |____| |_) / _ \| '__| __\___ \ / __/ _` | '_ \\
 | ||  __/_____|  __/ (_) | |  | |_ ___) | (_| (_| | | | | 
|___|_|        |_|   \___/|_|   \__|____/ \___\__,_|_| |_|
    '''
    print(banner)
    parser = argparse.ArgumentParser(description='存活扫描及端口扫描')
    parser.add_argument("-i", help="指定IP:192.168.1.0/24,192.168.2.1-192.168.2.254,www.baidu.com")
    parser.add_argument("-f", help="指定文件,文件一行一个目标")
    parser.add_argument("-m", help="指定方式", choices=['live', 'port', 'all'], default='live')
    parser.add_argument("-t", help="设置线程(default=3000)", default=3000)
    args = parser.parse_args()
    ip = args.i
    if ip is None:
        print("usage: IP-PortScan.py [-h] [-i IP] [-f FILE] [-m {live,port,all}] [-t THREAD]")
    print(args)
    time1 = time.time()
    Dispatch(args).main()
    time2 = time.time()
    print("任务用时", (time2 - time1))
