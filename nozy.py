#!/usr/bin/env python3

from pyfiglet import Figlet
import argparse
import socket
import requests
import dns.resolver
import nmap
import whois
import sys
import subprocess
import pkg_resources
from colorama import init, Fore
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

def update_packages():
    """تحديث المكتبات والحزم تلقائياً"""
    print(f"{Fore.BLUE}[*] جاري التحقق من التحديثات...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        requirements = pkg_resources.parse_requirements(open('requirements.txt'))
        for requirement in requirements:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', str(requirement)])
        print(f"{Fore.GREEN}[+] تم تحديث جميع المكتبات بنجاح")
    except Exception as e:
        print(f"{Fore.RED}[-] فشل في تحديث المكتبات: {str(e)}")

class NozyScan:
    def __init__(self):
        self.target = None
        self.mode = None
        self.results = {}
        self.nm = nmap.PortScanner()
        self.session = requests.Session()
        self.session.verify = False  # تجاوز شهادات SSL
        # تجاهل تحذيرات SSL
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def validate_target(self, target):
        """التحقق من صحة الهدف (IP، نطاق، بريد إلكتروني)"""
        if '@' in target:  # بريد إلكتروني
            return True
        try:
            socket.inet_aton(target)  # IP
            return True
        except socket.error:
            try:
                dns.resolver.resolve(target)  # نطاق
                return True
            except:
                return False

    def gather_info(self):
        """جمع المعلومات الأساسية عن الهدف"""
        print(f"{Fore.BLUE}[*] جاري جمع المعلومات عن {self.target}...")
        
        if '@' in self.target:  # بريد إلكتروني
            domain = self.target.split('@')[1]
        else:
            domain = self.target

        try:
            domain_info = whois.whois(domain)
            self.results['whois'] = domain_info
            print(f"{Fore.GREEN}[+] معلومات النطاق:")
            print(f"    المسجل: {domain_info.registrar}")
            print(f"    تاريخ التسجيل: {domain_info.creation_date}")
        except:
            print(f"{Fore.RED}[-] فشل في جمع معلومات النطاق")

    def scan_network(self):
        """فحص الشبكة والمنافذ المفتوحة"""
        print(f"{Fore.BLUE}[*] جاري فحص الشبكة...")
        try:
            self.nm.scan(self.target, arguments='-sV -sS -T4')
            for host in self.nm.all_hosts():
                print(f"{Fore.GREEN}[+] النتائج لـ {host}:")
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        print(f"    المنفذ {port}/{proto}: {service['name']} {service['version']}")
        except Exception as e:
            print(f"{Fore.RED}[-] فشل في فحص الشبكة: {str(e)}")

    def scan_web(self):
        """فحص تطبيق الويب"""
        print(f"{Fore.BLUE}[*] جاري فحص تطبيق الويب...")
        try:
            url = f"http://{self.target}"
            response = self.session.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            print(f"{Fore.GREEN}[+] معلومات الخادم:")
            print(f"    نوع الخادم: {headers.get('Server', 'غير معروف')}")
            print(f"    التقنيات: {headers.get('X-Powered-By', 'غير معروف')}")
        except Exception as e:
            print(f"{Fore.RED}[-] فشل في فحص تطبيق الويب: {str(e)}")

    def run(self, target, mode):
        """تشغيل الفحص"""
        self.target = target
        self.mode = mode

        if not self.validate_target(target):
            print(f"{Fore.RED}[-] هدف غير صالح")
            return

        if mode == 'recon':
            self.gather_info()
        elif mode == 'network':
            self.scan_network()
        elif mode == 'web':
            self.scan_web()
        elif mode == 'full':
            self.gather_info()
            self.scan_network()
            self.scan_web()

def print_banner():
    """عرض شعار البرنامج ومعلومات المبرمج"""
    f = Figlet(font='slant')
    print(f"{Fore.GREEN}{f.renderText('Nozy Scanner')}")
    print(f"{Fore.GREEN}Developed by: Saudi Linux")
    print(f"{Fore.GREEN}Contact: SaudiLinux7@gmail.com\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Nozy - أداة فحص أمني متكاملة')
    parser.add_argument('target', help='الهدف (IP، نطاق، بريد إلكتروني)')
    parser.add_argument('--mode', choices=['recon', 'network', 'web', 'full'],
                        default='recon', help='وضع الفحص')
    parser.add_argument('--no-update', action='store_true',
                        help='تخطي تحديث المكتبات')
    args = parser.parse_args()

    if not args.no_update:
        update_packages()

    scanner = NozyScan()
    scanner.run(args.target, args.mode)

if __name__ == '__main__':
    main()