from ipsherlock import *

class Colors:
    BLUE = "\033[94m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    RESET = "\033[0m"

class IPSherlockGraphic:
    LOGO = F"{Colors.BLUE}" + r'''
  _____ _____     _____ _               _            _    
 |_   _|  __ \   / ____| |             | |          | |   
   | | | |__) | | (___ | |__   ___ _ __| | ___   ___| | __
   | | |  ___/   \___ \| '_ \ / _ \ '__| |/ _ \ / __| |/ /
  _| |_| |       ____) | | | |  __/ |  | | (_) | (__|   <
 |_____|_|      |_____/|_| |_|\___|_|  |_|\___/ \___|_|\_\
 '''

    @staticmethod
    def CLEAR():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def INFO(label, value):
        print(f"{Colors.BLUE} {label}{Colors.BLUE}:{Colors.RESET} {value}{Colors.RESET}")

    @staticmethod
    def ERROR(msg):
        print(f"{Colors.RED} [ERROR] {msg}{Colors.RESET}")

    @staticmethod
    def NOTICE(msg):
        print(f"{Colors.YELLOW} [NOTICE] {msg}{Colors.RESET}")
