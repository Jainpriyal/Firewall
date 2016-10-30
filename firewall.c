#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

static struct nf_hook_ops netfilter_ops_in; /* NF_IP_PRE_ROUTING */
unsigned int src_port =0;
unsigned int dest_port = 0;
unsigned int src_ip =0;
unsigned int dest_ip = 0;
struct tcphdr *tcp_header;
struct iphdr *ip_header;
struct sk_buff *sock_buff;
struct icmphdr *icmph;
// ip of web server
static unsigned char *ip_address = "\xC0\xA8\x01\x03";
unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
sock_buff = skb;
ip_header = (struct iphdr *)skb_network_header(sock_buff);
if(!sock_buff)
{
return NF_ACCEPT;
}

//Get ip header
src_ip = ip_header->saddr;
dest_ip = ip_header->daddr;
printk(KERN_ALERT "dest ip %pI4", &dest_ip);

//Case1, analysing ICMP header
if(ip_header->protocol ==1)
{
icmph = icmp_hdr(sock_buff);
if((icmph->type == ICMP_ECHO) && (dest_ip != *(unsigned int*)ip_address) && (strcmp(in->name, "eth1")==0))
{
printk(KERN_INFO "Case1: Block ICMP echo requests from outside\n");
printk(KERN_INFO "Dropped! Cause: Icmp requests coming on interface: %s destination ip %pI4\n", in->name, &dest_ip);
return NF_DROP;
}
}

// Get TCP header
if (ip_header->protocol == 6){
tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);
dest_port = (unsigned int)ntohs(tcp_header->dest);
printk(KERN_ALERT "TCP connection");
printk(KERN_ALERT "dst port %d", dest_port);
}

//case2 block ssh connections
if ((strcmp(in->name, "eth1")==0) && dest_port == 22)
{
printk(KERN_INFO "Case2: Drop ssh connection from outside\n");
printk(KERN_INFO "Dropped! Cause: SSH request coming from %pI4 : on interface %s\n", &src_ip, in->name);
return NF_DROP;
}

//case3 block http requests
if((dest_port ==80) && dest_ip != *(unsigned int*)ip_address && (strcmp(in->name, "eth1")==0) )
{
printk(KERN_INFO "Case3: Block http requests from outside except the one going to server\n");
printk(KERN_INFO "Dropped! Cause: HTTP request coming from %pI4 : on interface %s", &src_ip, in->name);
return NF_DROP;
}

//default settings for all other ports
return NF_ACCEPT;
}

int init_module()
{
    netfilter_ops_in.hook = main_hook;
    netfilter_ops_in.pf = PF_INET;
    netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops_in.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&netfilter_ops_in); /* register NF_IP_PRE_ROUTING hook */
return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&netfilter_ops_in); /*unregister NF_IP_PRE_ROUTING hook*/
}

