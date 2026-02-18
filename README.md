Mr. Fetcher is a universal packet sniffer written in Python.

This tool allows you to analyze internet traffic on the operating system running Mr. Fetcher. This tool is essentially a simpler version of Wireshark. Unlike Wireshark, Mr. Fetcher works exclusively in the console and offers filtering and logging capabilities. Python 3.13+ and root access are required to run the tool.
#How to install?

Clone the repository using git.

If you don't have git installed, install it with the command:
```
sudo apt install git -y
```


```
git clone https://github.com/vesel4akProjects/MrFetcher.git
```

Go to the project folder.
```
cd Mr.Fetcher
```

#Install the dependencies.

```
sudo pip install -r requirements.txt
```

#Run Mr.Fetcher.

If your operating system is Windows, you can directly run 'mrfetcher.exe'

You can also compile Mr. Fetcher yourself into an .exe file. To do this, delete mrfetcher.exe and then run:
```
pyinstaller -F mrfetcher.py
```

Next, navigate to the dist folder; your .exe file will be there.

If you're using Linux or macOS, run:
```
sudo python3 mrfetcher.py
```
This option will launch Mr. Fetcher by default without any configuration.


#Flags and options
For a complete overview, run:
```
python mrfetcher.py --help
```
This will give you a full list of flags.

-i --iface — select an interface.

Example run:
```
sudo python3 mrfetcher.py --iface etho0
```
Mr. Fetcher checks the number of network interfaces on your operating system.

-t --timeout — select a timeout for packet capture. The default is 0.7 seconds. This is done to minimize the load on the terminal, but you can enter 0 seconds to capture packets without delay.

Example run:
```
sudo python3 mrfetcher.py --timeout 0
```
-m --mode — capture specific packets. This flag will allow you to capture ONLY one specific packet type. Currently, to capture more than one packet type, you will need to run Mr Fetcher separately for each. Important! To capture a packet, you must write the protocol name in capital letters!

Example run:
```
sudo python3 mrfetcher.py --mode DNS
```
-o --output — logging file. This flag is responsible for logging all captured packets. By default, all captured packets are saved to the file mrfetcher.txt, but you can specify a custom file. You cannot omit logging captured packets!

Example run:
```
sudo python3 mrfetcher.py --output "MyLogFile.log"
```
-f, --filter: BPF filter, like in Wireshark. The filter works on the same principle. Want to capture traffic only on port 80? Enter --filter "tcp port 80." By default, the filter is not configured.

Example run:
```
sudo python3 mrfetcher.py --filter "tcp port 9050"
```
-c, --count: Stop capturing traffic after N packets. For example, if you only want to capture 20 packets, enter --count 20. The default value is None.

Example run:
```
sudo python3 mrfetcher.py --count 30
```
#Important clarifications!

I do not recommend using --filter and --mode simultaneously. The tool may crash and produce errors. If you only need to capture a specific protocol, use --mode. If you need to capture multiple protocols or specify a condition, use --filter instead of --mode.

What will be added in the future?

We plan to add 6 new flags and new improvements in the future:

--host flag: Allows you to capture traffic only on a specific host or hosts. The behavior will be the same as with --mode and --filter.

--port flag: Allows you to capture traffic only on a specific port or ports. The behavior is similar.

--hunter flag: Narrow mode for capturing unencrypted HTTP traffic.

--save flag: Allows you to save to a .pcap file.

--json flag: Allows you to save to a .json file.

--extended flag: Allows you to analyze packets more deeply, performing a similar function in Wireshark.

We plan to improve this by adding the ability to view multiple protocols in --mode and also by not capitalizing protocols, such as DNS.

#Ethical Standards:

This tool is intended for training in cybersecurity, traffic analysis, network understanding, and system administration. It is very useful on low-power systems or systems without a graphical interface. Mr. Fetcher is also useful in CTF competitions or penetration testing.

THE AUTHOR WILL NOT BE LIABLE FOR THE USE OF HIS SOFTWARE FOR ILLEGAL PURPOSES!
