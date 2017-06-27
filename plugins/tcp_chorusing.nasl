#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10276);
 script_version ("$Revision: 1.30 $");

 script_cve_id("CVE-1999-1201");
 script_bugtraq_id(225);
 script_osvdb_id(218);
 
 script_name(english:"TCP/IP 'Chorusing' Windows DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote OS may facilitate a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"Microsoft Windows 95 and 98 clients have the ability
to bind multiple TCP/IP stacks on the same MAC address,
simply by having the protocol added more than once
in the Network Control panel.

The remote host has several TCP/IP stacks with the
same IP bound on the same MAC address. As a result,
it will reply several times to the same packets,
such as by sending multiple ACK to a single SYN,
creating noise on your network. If several hosts
behave the same way, then your network will be 
brought down." );
 script_set_attribute(attribute:"solution", value:
"Remove all the IP stacks except one in the remote
host." );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/02/06");
 script_cvs_date("$Date: 2011/03/21 01:21:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Counts the number of ACKs to a SYN";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("os_fingerprint.nasl");
 script_exclude_keys("SMB/WindowsVersion");

 
 exit(0);
}

#
# The script code starts here
#

# do not test this bug locally

if(islocalhost())exit(0);

# broken
exit(0);

if ( TARGET_IS_IPV6 ) exit(0);
os = get_kb_item("Host/OS");
if(os)
{
 if("Windows 9" >!< os)exit(0);
}


port = get_host_open_port();
if(!port)port = 21;

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_TCP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

tcp = forge_tcp_packet(ip:ip, th_sport:10003, th_dport:port, 
		       th_win:4096,th_seq:rand(), th_ack:0,
		       th_off:5, th_flags:TH_SYN, th_x2:0,th_urp:0);
		       
filter = string("tcp and src host ", get_host_ip(), " and dst host ",
this_host(), " and src port ", port, " and dst port ", 10003);
r = send_packet(tcp, pcap_active:TRUE, pcap_filter:filter);
if(r)
{
 r2 = pcap_next(pcap_filter:filter, timeout:5);
 if(r2)security_warning(port:0);
}

