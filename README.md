Changes
=========
Before inserting firewall, please make below changes in the firewall code:

1. Change it to your web server ip: 
   static unsigned char *ip_address = "\xC0\xA8\x01\x03"
   
2. Also change eth1 to the interface name by which web client is connected with firewall

Running firewall
==================
To insert firewall module please run following command: 

1. make  

2. insmod firewall.ko

After running make you will get output like this:

root@Firewall:~# make
make -C /lib/modules/3.13.0-68-generic/build M=/root modules
make[1]: Entering directory `/usr/src/linux-headers-3.13.0-68-generic'
 CC [M]  /root/firewall.o
/root/firewall.c: In function ‘init_module’:
/root/firewall.c:79:27: warning: assignment from incompatible pointer type [enabled by default]
    netfilter_ops_in.hook = main_hook;
                          ^
 Building modules, stage 2.
 MODPOST 1 modules
 LD [M]  /root/firewall.ko
make[1]: Leaving directory `/usr/src/linux-headers-3.13.0-68-generic'

3. To check information about that module:

root@Firewall:~# modinfo firewall.ko
filename:       /root/firewall.ko
srcversion:     5E8AB462D88D98EABC598BC
depends:        
vermagic:       3.13.0-68-generic SMP mod_unload modversions 

To remove firewall module please run following command:

1. rmmod firewall

System detail
===============
This code is tested in below linux environment:
Ubuntu 14.04
root@Firewall:~# uname -a
Linux Firewall 3.13.0-68-generic #111-Ubuntu SMP Fri Nov 6 18:17:06 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

