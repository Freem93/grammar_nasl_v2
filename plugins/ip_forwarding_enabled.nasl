#TRUSTED 4271a17bc2b3d528b8d9bc02b0c9a28248f2aa5a767d3ded7937b2666b1ad61b19c9c34d45929b8aa5c2a0c0e78fcd4c88a3da0bc26ad5e34353cedf239500cf5c91d3a07da3fd9204f5e998b2113012d8da8d16846c28499802581d3564425b32e28b89312b98646937a9f6e36f138cd8829bc7adebc9e8a277f0048d5b896d88dcb7f897258419ed81c1f0f462c0d08d862d8d2a8e3dd74a3f351324a8c6e0fab43e715b1bd621ea5cac60665c229d061ec6f732ee3f5a4a5ca49d2c04eae05535880359cf02ff6e3a487c338d9b747d7166fff1a8737966e43d96aaa7eb49a993c1f95fbe54fd77fc32d192ea2409c5c50546aba5849c473db28e79a16423ff85f082ea6493c50d306fe9aceb19a87f752160b36ef9d6902b1822b847c54d2a58262fff320fc1cad492c702f7f5349e454c364b4ddc85787fa95bc764e8de4f6c5c9042e8b9d122a3daacb92912859a52948a5d91b9626d9edd26b0fc22108ea57582baefd0a114df7a52400859eaf7b5939606c2a1de93859b7736cc6b7dd6413accce3403c6d32af1937acc7af43350358e1d770e867e09af8b35ed9d22242f9bc8445b83dad7018bbfa7752deb2db352a6d05c12e90c3764425d0c361b4cbd1616c5471d3a268c9a59b0d5160c09cbd57d6aa5428ebd89be43bf0be0195dc2556b559c5bd214f5d9f1acdee79fb85b7660f2fc01d3ddca32f4bcdecd8d
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("inject_packet") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(50686);
 script_version("1.7");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/07/16");

 script_cve_id("CVE-1999-0511");
 script_osvdb_id(8114);

 script_name(english:"IP Forwarding Enabled");
 script_summary(english:"Determines whether IP forwarding is enabled on the remote host.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has IP forwarding enabled.");
 script_set_attribute(attribute:"description", value:
"The remote host has IP forwarding enabled. An attacker can exploit
this to route packets through the host and potentially bypass some
firewalls / routers / NAC filtering. 

Unless the remote host is a router, it is recommended that you disable
IP forwarding.");
 script_set_attribute(attribute:"solution", value:
"On Linux, you can disable IP forwarding by doing :

echo 0 > /proc/sys/net/ipv4/ip_forward

On Windows, set the key 'IPEnableRouter' to 0 under

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters

On Mac OS X, you can disable IP forwarding by executing the command :

sysctl -w net.inet.ip.forwarding=0

For other systems, check with your vendor.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 exit(0);
}

include("raw.inc");

if ( TARGET_IS_IPV6 ) exit(0, "IPv4 check.");
if ( islocalhost() ) exit(0, "Can't check against localhost.");
if ( ! islocalnet() ) exit(1, "Remote host is not on the local network.");
ll = link_layer();
if ( strlen(ll) < 14 ) exit(0, "Not ethernet.");

udp_src = rand() % 64000 + 1024;
udp_dst = rand() % 64000 + 1024;
src = string("169.254.", rand()%253 + 1, ".", rand()%253 + 1);
smac = get_local_mac_addr();
dmac = get_gw_mac_addr();

pkt = mkpacket(ip(ip_p:IPPROTO_UDP, ip_src:src, ip_dst:this_host()), udp(uh_sport:udp_src, uh_dport:udp_dst));
ethernet = dmac + smac + mkword(0x0800);

me  = get_local_mac_addr();
filt = NULL;
for ( i = 0 ; i < 6 ; i ++ )
{
 if ( filt ) filt += " and ";
 filt += "ether[" + i + "] = " + getbyte(blob:me, pos:i) + " ";
}
for ( i = 0 ; i < 3; i ++ )
{
 r = inject_packet(packet:ethernet + pkt, filter:"udp and src port " + udp_src + " and dst port " + udp_dst + " and src host " + src + " and dst host " + this_host() + " and " + filt , timeout:1);
 if ( r ) break;
}

if ( r )
{
 if ( substr(r, 0, 5) == get_local_mac_addr() &&
      substr(r, 6, 11) == dmac ) security_warning(0);
}
else exit(0, "IP forwarding is not enabled on the remote host.");
