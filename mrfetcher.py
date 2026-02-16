
from scapy.all import *
import argparse
from colorama import init, Fore, Style
from time import sleep
from datetime import datetime
from sys import exit
import warnings
warnings.filterwarnings("ignore") 
init(True)


class MrFetcher:
    def __init__(self, timeout=0.5, iface=None, mode="all", output="mrfetcher.txt", filter="", counts=None):

        self.timeout = timeout
        self.iface = iface
        self.mode = mode
        self.output = output
        self.filter = filter
        self.counts = counts
        self.total = 1
        self.scapy_protocols = None
        
        try:

            self.scapy_protocols = set()

           
            global_vars = globals()
            for var_name, var_value in global_vars.items():
                if isinstance(var_value, type):
                    if issubclass(var_value, Packet):
                        self.scapy_protocols.add(var_name)


        except:
            self.scapy_protocols = set() 
 
        if self.mode != "all":

            mode_upper = self.mode.upper()
            found = False

            for p in self.scapy_protocols:

                if p.upper() == mode_upper:
                    found = True
                    break

            if not found:

                print(Style.BRIGHT + Fore.RED + f"[-]Protocol '{self.mode}' not supported")
                exit(1)

        if self.timeout < 0:
            print(Style.BRIGHT + Fore.RED + f"[-]Timeout cannot be negative")
            exit(1)

        self.total_interfaces = set()
        for iface_name, iface_obj in conf.ifaces.items():
            if iface_obj and hasattr(iface_obj, 'name') and iface_obj.name:
                self.total_interfaces.add(iface_obj.name)


        if self.iface:

            if self.iface not in self.total_interfaces:

                print(Style.BRIGHT + Fore.RED + f"[-]Interface '{self.iface}' not found")
                print(Style.BRIGHT + Fore.YELLOW + "[*]Available interfaces:")

                try:

                    for iface in sorted([i for i in self.total_interfaces if i]):
                        print(f"    {iface}")

                except:

                    for iface in self.total_interfaces:
                        if iface:

                            print(f"    {iface}")
                exit(1)

    def log(self, packet):

        try:

            with open(self.output, "a", encoding="utf-8") as file:
                file.write(f"\n[+][{datetime.now()}]Intercepted: {packet.summary()}")

        except:
            pass  
        
    def greeting(self):
        return print(Style.BRIGHT + Fore.LIGHTWHITE_EX + """

███╗   ███╗██████╗     ███████╗███████╗████████╗ ██████╗██╗  ██╗███████╗██████╗ 
████╗ ████║██╔══██╗    ██╔════╝██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔══██╗
██╔████╔██║██████╔╝    █████╗  █████╗     ██║   ██║     ███████║█████╗  ██████╔╝
██║╚██╔╝██║██╔══██╗    ██╔══╝  ██╔══╝     ██║   ██║     ██╔══██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║    ██║     ███████╗   ██║   ╚██████╗██║  ██║███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝     ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝



                                    made by vesel4ak

""")
        
    def packet_handler(self, packet):
        try:

            if self.mode == "all":

                print(Style.BRIGHT + Fore.GREEN + f"[+]" + 
                          Style.BRIGHT + Fore.LIGHTYELLOW_EX + f"[Packet #{self.total}]   " +
                          Style.BRIGHT + Fore.LIGHTWHITE_EX + f"[{datetime.now()}]   "
                      + Style.BRIGHT + Fore.CYAN + f"Intercepted: {packet.summary()}")
                
                self.log(packet)
                sleep(self.timeout)
                self.total +=1

            else:

                if packet.haslayer(eval(self.mode)): 
                    
                    print(Style.BRIGHT + Fore.GREEN + f"[+]" + 
                          Style.BRIGHT + Fore.LIGHTYELLOW_EX + f"[Packet #{self.total}]   " +
                          Style.BRIGHT + Fore.LIGHTWHITE_EX + f"[{datetime.now()}]   "
                      + Style.BRIGHT + Fore.CYAN + f"Intercepted: {packet.summary()}")
                    
                    self.log(packet)
                    self.total +=1
                    sleep(self.timeout)

        except KeyboardInterrupt:

            print(Style.BRIGHT + Fore.RED + f"[!]{datetime.now()}   END MR FETCHER")
            exit(0)

        except Exception as error:
            print(Style.BRIGHT + Fore.RED + f"[!]ERROR : {error}]")

    def start_sniff(self):

        self.greeting()
        sleep(3)

        try:

            with open(self.output, "a", encoding="utf-8") as file:
                file.write(f"\n[!]{datetime.now()}   START MR FETCHER")
        except:

            pass
        
        print(Style.BRIGHT + Fore.RED + f"[!]{datetime.now()}   START MR FETCHER")

        sniff_params = {
            "prn": self.packet_handler,
            "store": False
        }
        
        if self.counts is not None:
            sniff_params['count'] = self.counts
            
        if self.iface:
            sniff_params['iface'] = self.iface
        
        if self.filter:
            sniff_params['filter'] = self.filter


        try:
            return sniff(**sniff_params)
        
        except Exception as e:

            print(Style.BRIGHT + Fore.RED + f"[-]Sniffing error: {e}")
            print(Style.BRIGHT + Fore.YELLOW + "[*]Try running with administrator privileges")
            exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Mr Fetcher - Network Packet Sniffer")
    parser.add_argument("-i", "--iface", type=str, help="Interface to sniff on")
    parser.add_argument("-t", "--timeout", type=float, default=0.7, help="Timeout between packets")
    parser.add_argument("-m", "--mode", type=str, default="all", help="Protocol to filter")
    parser.add_argument("-o", "--output", type=str, default="mrfetcher.txt", help="Output log file")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter")
    parser.add_argument("-c", "--count", type=int, default=None, help="Packets count")
    
    args = parser.parse_args()
    
    fetcher = MrFetcher(
        timeout=args.timeout,
        iface=args.iface,
        mode=args.mode,
        output=args.output,
        filter=args.filter,
        counts=args.count
    )

    fetcher.start_sniff()


        
        


