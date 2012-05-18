# junipervpn.py

Juniper VPN two-factor authentication automation

* Original code: http://code.google.com/p/juniper-vpn/
* More details: http://makefile.com/.plan/2009/10/juniper-vpn-64-bit-linux-an-unsolved-mystery/

## Requirements

* Sun/Oracle JRE/JDK (including browser plugin)
* gcc compiler

## Installation & Usage

1. Authenticate to your Juniper web interface, and launch Network Connect.  This should place the needed files in your ~/.juniper_networks directory.

2. Install gcc-multilib for 32bit compiler/linker support
```bash
   sudo apt-get install gcc-multilib
```
3. Convert Juniper's ncui.so into an executable:
```bash
cd ~/.juniper_networks/network_connect
gcc -m32 -Wl,-rpath,`pwd` -o ncui libncui.so
sudo chown root:root ncui
sudo chmod 4775 ncui
```
4. Download your Juniper SSL certificate:
```bash
cd ~/.juniper_networks/network_connect
echo | openssl s_client -connect junipervpn.example.com:443 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -outform der > ssl.crt
```bash
5. Create the config file: 
```bash
    python junipervpn.py --create
```
6. Start the client:
```bash
    python junipervpn.py
```