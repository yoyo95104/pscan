#include <linux/errno.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

static char *ip = NULL;
static char *dip = NULL;
static int targetport = 0;
static int proto = 0;
static int rangestart = 0;
static int rangeend = 0;

module_param(ip, charp, 0644);
module_param(dip, charp, 0644);
module_param(targetport, int, 0644);
module_param(proto, int, 0644);
module_param(rangestart, int, 0644);
module_param(rangeend, int, 0644);

MODULE_PARM_DESC(rangestart, "Start of Blocking port range");
MODULE_PARM_DESC(rangeend, "End of Blocking port tange");
MODULE_PARM_DESC(ip, "Source IP to block");
MODULE_PARM_DESC(dip, "Destination IP to block");
MODULE_PARM_DESC(targetport, "Destination port to block");
MODULE_PARM_DESC(proto, "Protocol");

static __be32 filter_ip = 0;
static __be32 filterd_ip = 0;

static struct nf_hook_ops nfho;

static unsigned int hook_fn(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state) {
  struct iphdr *iph;
  if (!skb)
    return NF_ACCEPT;
  if (skb->protocol != htons(ETH_P_IP))
    return NF_ACCEPT;
  if (!pskb_may_pull(skb, sizeof(struct iphdr)))
    return NF_ACCEPT;
  iph = ip_hdr(skb);
  if (!iph)
    return NF_ACCEPT;
  if (filter_ip && iph->saddr == filter_ip)
    return NF_DROP;
  if (filterd_ip && iph->daddr == filterd_ip)
    return NF_DROP;
  if (proto && iph->protocol == proto)
    return NF_DROP;
  if (targetport) {
    if (iph->protocol == IPPROTO_TCP) {
      if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;
      struct tcphdr *tcph = tcp_hdr(skb);
      if (ntohs(tcph->dest) == targetport)
        return NF_DROP;
    } else if (iph->protocol == IPPROTO_UDP) {
      if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
        return NF_ACCEPT;
      struct udphdr *udph = udp_hdr(skb);
      if (ntohs(udph->dest) == targetport)
        return NF_DROP;
    }
  }
  if (rangeend > 0 && rangestart > 0) {
    if (iph->protocol == IPPROTO_TCP) {
      if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
        return NF_ACCEPT;
      struct tcphdr *tcph = tcp_hdr(skb);
      if (ntohs(tcph->source) >= rangestart && ntohs(tcph->source) <= rangeend)
        return NF_DROP;
    } else if (iph->protocol == IPPROTO_UDP) {
      if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
        return NF_ACCEPT;
      struct udphdr *udph = udp_hdr(skb);
      if (ntohs(udph->source) >= rangestart && ntohs(udph->source) <= rangeend)
        return NF_DROP;
    }
  }
  return NF_ACCEPT;
}

static int __init filter_init(void) {
  int ret;
  if (ip && strcmp(ip, "NULL") != 0) {
    if (in4_pton(ip, -1, (u8 *)&filter_ip, -1, NULL) <= 0) {
      printk(KERN_ERR "Invalid source IP\n");
      return -EINVAL;
    }
    printk(KERN_INFO "Blocking Source IP: %s\n", ip);
  }
  if (dip && strcmp(dip, "NULL") != 0) {
    if (in4_pton(dip, -1, (u8 *)&filterd_ip, -1, NULL) <= 0) {
      printk(KERN_ERR "Invalid destination IP\n");
      return -EINVAL;
    }
    printk(KERN_INFO "Blocking Destination IP: %s\n", dip);
  }
  printk(KERN_INFO "filter: loaded with rangestart=%d rangeend=%d "
                   "targetport=%d proto=%d ip=%s dip=%s "
                   " \n",
         rangestart, rangeend, targetport, proto, ip ? ip : "NULL",
         dip ? dip : "NULL");
  nfho.hook = hook_fn;
  nfho.pf = PF_INET;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.priority = NF_IP_PRI_FIRST;
  ret = nf_register_net_hook(&init_net, &nfho);
  if (ret) {
    printk(KERN_ERR "Failed to register Netfilter hook\n");
    return ret;
  }
  printk(KERN_INFO "Netfilter module loaded\n");
  return 0;
}

static void __exit filter_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);
  printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pscan");
MODULE_DESCRIPTION("Network Packet Filter");
