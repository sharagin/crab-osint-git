#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import socket
import whois
import requests
import re
import dns.resolver
import ipaddress
from datetime import datetime
import argparse
import time
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import ssl
from pystyle import Colors, Colorate, Write, System, Center

class CrabOSINT:
    def __init__(self):
        self.version = "2.0"
        self.author = "dis0nan"
        self.name = "🦀 Crab OSINT Tool 🦀"
        
        self.banner = r"""
     ________      ________      ________      ________     
|\   ____\    |\   __  \    |\   __  \    |\   __  \    
\ \  \___|    \ \  \|\  \   \ \  \|\  \   \ \  \|\ /_   
 \ \  \        \ \   _  _\   \ \   __  \   \ \   __  \  
  \ \  \____    \ \  \\  \|   \ \  \ \  \   \ \  \|\  \ 
   \ \_______\   \ \__\\ _\    \ \__\ \__\   \ \_______\
    \|_______|    \|__|\|__|    \|__|\|__|    \|_______|
                                                        
                                                        
                                                        
               Многофункциональный OSINT Инструмент
                   Разработчик: dis0nan v{}
        """.format(self.version)
        
        self.menu_items = [
            "1. 📍 Информация о домене",
            "2. 🌍 Геолокация IP",
            "3. 🔍 Поиск поддоменов", 
            "4. 🚪 Сканирование портов",
            "5. 📄 WHOIS информация",
            "6. 🔗 Проверка ссылок",
            "7. 📊 DNS анализ",
            "8. 🏢 Информация о компании",
            "9. 💾 Сохранить все данные",
            "10. 🎯 Полный анализ цели",
            "0. 🚪 Выход"
        ]
        
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cdn', 'cloud', 'api', 'secure', 'vpn', 'shop', 'blog', 'dev', 'test',
            'staging', 'portal', 'cpanel', 'webdisk', 'autodiscover', 'imap'
        ]
        
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 
                           993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 2086,
                           2087, 2095, 2096, 2222, 3306, 3389, 5432, 5900,
                           5985, 6379, 8080, 8443, 8888, 9000, 9200, 27017]
        
        self.results = {}
        
    def clear_screen(self):
        """Очистить экран"""
        System.Clear()
    
    def display_banner(self):
        """Показать баннер с крабом"""
        self.clear_screen()
        colored_banner = Colorate.Horizontal(
            Colors.DynamicMIX((Colors.orange, Colors.yellow, Colors.red)), 
            self.banner
        )
        print(colored_banner)
        
        # Анимированная строка состояния
        status_line = f"┌{'─'*58}┐\n"
        status_line += f"│{'Crab OSINT - Инструмент для разведки'.center(58)}│\n"
        status_line += f"│{'Разработчик: dis0nan'.center(58)}│\n"
        status_line += f"│{datetime.now().strftime('%d.%m.%Y %H:%M:%S').center(58)}│\n"
        status_line += f"└{'─'*58}┘"
        
        Write.Print(Center.XCenter(status_line) + "\n\n", Colors.orange, interval=0.001)
    
    def print_colored(self, text, color=Colors.orange, delay=0.02):
        """Цветной вывод текста"""
        Write.Print(text, color, interval=delay)
    
    def print_success(self, text):
        """Вывод успешного сообщения"""
        Write.Print(f"[✓] {text}\n", Colors.green, interval=0.01)
    
    def print_error(self, text):
        """Вывод сообщения об ошибке"""
        Write.Print(f"[✗] {text}\n", Colors.red, interval=0.01)
    
    def print_info(self, text):
        """Вывод информационного сообщения"""
        Write.Print(f"[i] {text}\n", Colors.blue, interval=0.01)
    
    def print_warning(self, text):
        """Вывод предупреждения"""
        Write.Print(f"[!] {text}\n", Colors.yellow, interval=0.01)
    
    def validate_domain(self, domain):
        """Проверка валидности домена"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None
    
    def validate_ip(self, ip):
        """Проверка валидности IP адреса"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_dns_records(self, domain):
        """Получить DNS записи домена"""
        records = {}
        record_types = {
            'A': 'Адрес IPv4',
            'AAAA': 'Адрес IPv6', 
            'MX': 'Почтовые серверы',
            'NS': 'DNS серверы',
            'TXT': 'Текстовые записи',
            'SOA': 'Начальная запись зоны',
            'CNAME': 'Канонические имена'
        }
        
        for rtype, description in record_types.items():
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = {
                    'описание': description,
                    'значения': [str(rdata) for rdata in answers]
                }
                self.print_success(f"Найдены {rtype} записи: {len(answers)} записей")
            except Exception as e:
                records[rtype] = {
                    'описание': description,
                    'ошибка': str(e)
                }
        
        return records
    
    def get_whois_info(self, domain):
        """Получить WHOIS информацию"""
        try:
            w = whois.whois(domain)
            info = {
                'домен': w.domain_name,
                'регистратор': w.registrar,
                'дата_создания': w.creation_date,
                'дата_окончания': w.expiration_date,
                'дата_обновления': w.updated_date,
                'серверы_доменов': w.name_servers,
                'статус': w.status,
                'администратор': w.admin if hasattr(w, 'admin') else None,
                'технический_контакт': w.tech if hasattr(w, 'tech') else None
            }
            self.print_success(f"WHOIS информация получена для {domain}")
            return info
        except Exception as e:
            self.print_error(f"Ошибка WHOIS: {str(e)}")
            return {"ошибка": str(e)}
    
    def get_ip_geolocation(self, ip):
        """Получить геолокацию по IP"""
        try:
            # Используем несколько источников
            sources = [
                f"http://ip-api.com/json/{ip}",
                f"https://ipinfo.io/{ip}/json"
            ]
            
            for url in sources:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        return {
                            'ip': data.get('ip', ip),
                            'страна': data.get('country', data.get('countryCode', 'Неизвестно')),
                            'регион': data.get('region', data.get('regionName', 'Неизвестно')),
                            'город': data.get('city', 'Неизвестно'),
                            'провайдер': data.get('isp', data.get('org', 'Неизвестно')),
                            'координаты': data.get('loc', 'Неизвестно'),
                            'часовой_пояс': data.get('timezone', 'Неизвестно'),
                            'asn': data.get('as', 'Неизвестно')
                        }
                except:
                    continue
            
            return {"ошибка": "Не удалось получить геолокацию"}
        except Exception as e:
            return {"ошибка": str(e)}
    
    def find_subdomains(self, domain):
        """Найти поддомены"""
        found_subdomains = []
        self.print_info(f"Поиск поддоменов для {domain}...")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for sub in self.common_subdomains:
                subdomain = f"{sub}.{domain}"
                futures.append(executor.submit(self.check_subdomain, subdomain))
            
            for future in futures:
                try:
                    result = future.result(timeout=2)
                    if result:
                        found_subdomains.append(result)
                        self.print_success(f"Найден: {result['поддомен']} → {result['ip']}")
                except:
                    pass
        
        return found_subdomains
    
    def check_subdomain(self, subdomain):
        """Проверить поддомен"""
        try:
            ip = socket.gethostbyname(subdomain)
            return {
                'поддомен': subdomain,
                'ip': ip,
                'время': datetime.now().strftime('%H:%M:%S')
            }
        except:
            return None
    
    def scan_ports(self, target, ports=None):
        """Сканировать порты"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        self.print_info(f"Сканирование портов для {target}...")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "неизвестно"
                    
                    open_ports.append({
                        'порт': port,
                        'сервис': service,
                        'статус': 'открыт'
                    })
                    return True
            except:
                pass
            return False
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            
            for future, port in zip(futures, ports):
                try:
                    if future.result(timeout=2):
                        self.print_success(f"Порт {port} открыт")
                except:
                    pass
        
        return open_ports
    
    def get_ssl_info(self, domain):
        """Получить информацию о SSL сертификате"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    info = {
                        'версия': cert.get('version'),
                        'серийный_номер': cert.get('serialNumber'),
                        'субъект': dict(x[0] for x in cert['subject']),
                        'издатель': dict(x[0] for x in cert['issuer']),
                        'действителен_с': cert.get('notBefore'),
                        'действителен_до': cert.get('notAfter')
                    }
                    
                    self.print_success(f"SSL информация получена для {domain}")
                    return info
        except Exception as e:
            self.print_error(f"Ошибка SSL: {str(e)}")
            return {"ошибка": str(e)}
    
    def get_http_headers(self, url):
        """Получить HTTP заголовки"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            response = requests.get(url, timeout=10, verify=False)
            headers = dict(response.headers)
            
            info = {
                'статус': response.status_code,
                'сервер': headers.get('Server', 'Неизвестно'),
                'технологии': self.detect_technologies(headers),
                'безопасность': self.check_security_headers(headers)
            }
            
            return info
        except Exception as e:
            return {"ошибка": str(e)}
    
    def detect_technologies(self, headers):
        """Определить используемые технологии"""
        technologies = []
        
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        return technologies if technologies else ["Не определено"]
    
    def check_security_headers(self, headers):
        """Проверить заголовки безопасности"""
        security = {}
        important_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options', 
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        for header in important_headers:
            security[header] = headers.get(header, "Отсутствует")
        
        return security
    
    def get_company_info(self, domain):
        """Получить информацию о компании"""
        try:
            # Извлекаем основное имя домена
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                company_name = domain_parts[-3]  # Второй уровень
            else:
                company_name = domain_parts[-2]  # Основное имя
            
            # Пытаемся найти информацию на сайте
            try:
                response = requests.get(f"https://{domain}", timeout=10)
                html = response.text
                
                # Поиск названия компании в HTML
                company_patterns = [
                    r'<title>(.*?)</title>',
                    r'<meta[^>]*name=["\']company["\'][^>]*content=["\'](.*?)["\']',
                    r'©\s*(.*?)\s*\d{4}',
                    r'&copy;\s*(.*?)\s*\d{4}'
                ]
                
                for pattern in company_patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        company_name = match.group(1).strip()
                        break
            except:
                pass
            
            info = {
                'предполагаемое_название': company_name.title(),
                'домен': domain,
                'дата_анализа': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
                'примечание': 'Информация собрана на основе открытых данных'
            }
            
            return info
        except Exception as e:
            return {"ошибка": str(e)}
    
    def full_domain_analysis(self, domain):
        """Полный анализ домена"""
        self.print_info(f"Начинаю полный анализ домена: {domain}")
        Write.Print(f"\n{'═'*70}\n", Colors.orange)
        
        all_results = {
            'цель': domain,
            'время_анализа': datetime.now().isoformat(),
            'автор_анализа': self.author
        }
        
        
        Write.Print("\n[📊] Анализ DNS записей:\n", Colors.cyan)
        all_results['dns'] = self.get_dns_records(domain)
        time.sleep(0.5)
        
        
        Write.Print("\n[📄] Получение WHOIS информации:\n", Colors.cyan)
        all_results['whois'] = self.get_whois_info(domain)
        time.sleep(0.5)
        
      
        Write.Print("\n[🔐] Анализ SSL сертификата:\n", Colors.cyan)
        all_results['ssl'] = self.get_ssl_info(domain)
        time.sleep(0.5)
        
        
        Write.Print("\n[🌐] Анализ HTTP заголовков:\n", Colors.cyan)
        all_results['http'] = self.get_http_headers(domain)
        time.sleep(0.5)
        
        
        Write.Print("\n[🔍] Поиск поддоменов:\n", Colors.cyan)
        all_results['поддомены'] = self.find_subdomains(domain)
        time.sleep(0.5)
        
        
        try:
            ip = socket.gethostbyname(domain)
            Write.Print(f"\n[📍] IP адрес: {ip}\n", Colors.green)
            all_results['ip_адрес'] = ip
            
            
            Write.Print("\n[🌍] Геолокация IP:\n", Colors.cyan)
            all_results['геолокация'] = self.get_ip_geolocation(ip)
            time.sleep(0.5)
            
            
            Write.Print("\n[🚪] Сканирование портов:\n", Colors.cyan)
            all_results['порты'] = self.scan_ports(ip)
            time.sleep(0.5)
        except Exception as e:
            self.print_error(f"Не удалось получить IP: {str(e)}")
        
        # 9. Информация о компании
        Write.Print("\n[🏢] Сбор информации о компании:\n", Colors.cyan)
        all_results['компания'] = self.get_company_info(domain)
        
        Write.Print(f"\n{'═'*70}\n", Colors.orange)
        self.print_success(f"Полный анализ домена {domain} завершен!")
        
        return all_results
    
    def save_results(self, data, filename=None):
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"crab_osint_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            
            self.print_success(f"Результаты сохранены в файл: {filename}")
            return filename
        except Exception as e:
            self.print_error(f"Ошибка сохранения: {str(e)}")
            return None
    
    def display_menu(self):
        self.display_banner()
        
        Write.Print("┌" + "─"*58 + "┐\n", Colors.orange)
        Write.Print("│" + "ГЛАВНОЕ МЕНЮ".center(58) + "│\n", Colors.yellow)
        Write.Print("├" + "─"*58 + "┤\n", Colors.orange)
        
        for item in self.menu_items:
            Write.Print(f"│ {item:<57}│\n", Colors.cyan, interval=0.01)
        
        Write.Print("└" + "─"*58 + "┘\n\n", Colors.orange)
    
    def display_results_table(self, title, data, indent=0):
        indent_str = " " * indent
        Write.Print(f"\n{indent_str}{'='*60}\n", Colors.orange)
        Write.Print(f"{indent_str}{title}\n", Colors.yellow)
        Write.Print(f"{indent_str}{'='*60}\n", Colors.orange)
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    Write.Print(f"\n{indent_str}├─ {key}:\n", Colors.cyan)
                    self.display_results_table("", value, indent + 4)
                elif isinstance(value, list):
                    Write.Print(f"\n{indent_str}├─ {key}:\n", Colors.cyan)
                    for i, item in enumerate(value, 1):
                        if isinstance(item, dict):
                            Write.Print(f"{indent_str}│  ├─ Элемент {i}:\n", Colors.white)
                            self.display_results_table("", item, indent + 6)
                        else:
                            Write.Print(f"{indent_str}│  ├─ {item}\n", Colors.white)
                else:
                    Write.Print(f"{indent_str}├─ {key}: ", Colors.cyan)
                    Write.Print(f"{value}\n", Colors.white)
        
        elif isinstance(data, list):
            for i, item in enumerate(data, 1):
                if isinstance(item, dict):
                    Write.Print(f"\n{indent_str}├─ Элемент {i}:\n", Colors.white)
                    self.display_results_table("", item, indent + 4)
                else:
                    Write.Print(f"{indent_str}├─ {item}\n", Colors.white)
        
        Write.Print(f"{indent_str}{'='*60}\n", Colors.orange)
    
    def run(self):
        while True:
            self.display_menu()
            
            try:
                choice = Write.Input("\n[🦀] Выберите действие (0-10): ", Colors.orange)
                
                if choice == '0':
                    self.print_info("Выход из программы...")
                    Write.Print("\nСпасибо за использование Crab OSINT! 🦀\n", Colors.green)
                    time.sleep(1)
                    break
                
                elif choice == '1':
                    domain = Write.Input("[📍] Введите домен: ", Colors.cyan)
                    if self.validate_domain(domain):
                        results = self.full_domain_analysis(domain)
                        self.display_results_table(f"Результаты анализа: {domain}", results)
                    else:
                        self.print_error("Неверный формат домена!")
                
                elif choice == '2':
                    ip = Write.Input("[🌍] Введите IP адрес: ", Colors.cyan)
                    if self.validate_ip(ip):
                        results = self.get_ip_geolocation(ip)
                        self.display_results_table(f"Геолокация IP: {ip}", results)
                    else:
                        self.print_error("Неверный формат IP адреса!")
                
                elif choice == '3':
                    domain = Write.Input("[🔍] Введите домен для поиска поддоменов: ", Colors.cyan)
                    if self.validate_domain(domain):
                        results = self.find_subdomains(domain)
                        self.display_results_table(f"Найденные поддомены: {domain}", results)
                    else:
                        self.print_error("Неверный формат домена!")
                
                elif choice == '4':
                    target = Write.Input("[🚪] Введите IP или домен для сканирования портов: ", Colors.cyan)
                    try:
                        if self.validate_ip(target):
                            ip = target
                        else:
                            ip = socket.gethostbyname(target)
                        
                        self.print_info(f"Сканирую порты для {ip}...")
                        results = self.scan_ports(ip)
                        self.display_results_table(f"Открытые порты: {ip}", results)
                    except Exception as e:
                        self.print_error(f"Ошибка: {str(e)}")
                
                elif choice == '5':
                    domain = Write.Input("[📄] Введите домен для WHOIS: ", Colors.cyan)
                    if self.validate_domain(domain):
                        results = self.get_whois_info(domain)
                        self.display_results_table(f"WHOIS информация: {domain}", results)
                    else:
                        self.print_error("Неверный формат домена!")
                
                elif choice == '6':
                    url = Write.Input("[🔗] Введите URL для проверки: ", Colors.cyan)
                    results = self.get_http_headers(url)
                    self.display_results_table(f"HTTP заголовки: {url}", results)
                
                elif choice == '7':
                    domain = Write.Input("[📊] Введите домен для DNS анализа: ", Colors.cyan)
                    if self.validate_domain(domain):
                        results = self.get_dns_records(domain)
                        self.display_results_table(f"DNS записи: {domain}", results)
                    else:
                        self.print_error("Неверный формат домена!")
                
                elif choice == '8':
                    domain = Write.Input("[🏢] Введите домен для поиска информации о компании: ", Colors.cyan)
                    if self.validate_domain(domain):
                        results = self.get_company_info(domain)
                        self.display_results_table(f"Информация о компании: {domain}", results)
                    else:
                        self.print_error("Неверный формат домена!")
                
                elif choice == '9':
                    if hasattr(self, 'last_results'):
                        filename = Write.Input("[💾] Введите имя файла (или нажмите Enter для автоимени): ", Colors.cyan)
                        if not filename:
                            filename = None
                        self.save_results(self.last_results, filename)
                    else:
                        self.print_error("Нет данных для сохранения!")
                
                elif choice == '10':
                    target = Write.Input("[🎯] Введите цель для полного анализа (домен/IP): ", Colors.cyan)
                    
                    if self.validate_domain(target):
                        self.last_results = self.full_domain_analysis(target)
                        self.display_results_table(f"Полный отчет по: {target}", self.last_results)
                    elif self.validate_ip(target):
                        self.print_info(f"Анализирую IP: {target}")
                        results = {
                            'ip_адрес': target,
                            'геолокация': self.get_ip_geolocation(target),
                            'порты': self.scan_ports(target)
                        }
                        self.last_results = results
                        self.display_results_table(f"Отчет по IP: {target}", results)
                    else:
                        self.print_error("Неверный формат цели!")
                
                else:
                    self.print_error("Неверный выбор!")
                
                if choice not in ['0', '9']:
                    Write.Input("\n[⏎] Нажмите Enter для продолжения...", Colors.gray)
            
            except KeyboardInterrupt:
                self.print_warning("\nПрервано пользователем")
                break
            except Exception as e:
                self.print_error(f"Ошибка: {str(e)}")
                time.sleep(2)

def main():
    try:
        # Проверка зависимостей
        required_modules = ['requests', 'whois', 'dnspython', 'pystyle']
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                Write.Print(f"[!] Не установлен модуль: {module}\n", Colors.red)
                Write.Print(f"[i] Установите: pip install {module}\n", Colors.blue)
                return
        
        tool = CrabOSINT()

        parser = argparse.ArgumentParser(description='Crab OSINT Tool - Инструмент для разведки')
        parser.add_argument('-d', '--domain', help='Анализ домена')
        parser.add_argument('-i', '--ip', help='Анализ IP адреса')
        parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
        parser.add_argument('--full', action='store_true', help='Полный анализ')
        
        args = parser.parse_args()
        
        if args.domain or args.ip:
            # Режим командной строки
            tool.display_banner()
            
            if args.domain:
                if args.full:
                    results = tool.full_domain_analysis(args.domain)
                else:
                    results = {
                        'dns': tool.get_dns_records(args.domain),
                        'whois': tool.get_whois_info(args.domain)
                    }
                
                tool.display_results_table(f"Результаты анализа: {args.domain}", results)
                
                if args.output:
                    tool.save_results(results, args.output)
            
            if args.ip:
                if tool.validate_ip(args.ip):
                    results = {
                        'геолокация': tool.get_ip_geolocation(args.ip),
                        'порты': tool.scan_ports(args.ip)
                    }
                    tool.display_results_table(f"Результаты анализа IP: {args.ip}", results)
                    
                    if args.output:
                        tool.save_results(results, args.output)
                else:
                    tool.print_error("Неверный формат IP адреса!")
        else:
            tool.run()
    
    except KeyboardInterrupt:
        Write.Print("\n\n[!] Программа прервана пользователем\n", Colors.red)
        Write.Print("[🦀] До свидания!\n", Colors.orange)
    except Exception as e:
        Write.Print(f"\n[✗] Критическая ошибка: {str(e)}\n", Colors.red)

if __name__ == "__main__":
    main()