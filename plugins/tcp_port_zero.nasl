#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18164);
 script_version ("$Revision: 1.11 $");
 script_cvs_date("$Date: 2011/03/11 21:52:40 $");
 script_name(english:"TCP Port 0 Open: Possible Backdoor");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has TCP port 0 open." );
 script_set_attribute(attribute:"description", value:
"TCP port 0 is open on the remote host. This is highly 
suspicious as this TCP port is reserved and should not 
be used. This might be a backdoor (REx)." );
 script_set_attribute(attribute:"see_also", value:"http://www.simovits.com/trojans/tr_data/y2814.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.bizsystems.com/downloads/labrea/localTrojans.pl" );
 script_set_attribute(attribute:"solution", value:
"Check your system." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();



 summary["english"] = "Open a TCP connection to port 0";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 exit(0);
}

# I'm not sure this works with any OS, so I wrote a pcap version
# s = open_sock_tcp(0);
# if (s) 
# {
#  security_warning(port: 0);	# Nessus API cannot really handle this
#  close(s);
# }

if ( islocalhost() ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

saddr = this_host();
daddr = get_host_ip();
sport = rand() % 64512 + 1024;
dport = 0;
filter = strcat('src port ', dport, ' and src host ', daddr, 
	' and dst port ', sport, ' and dst host ', saddr);

ip = forge_ip_packet(	ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
			ip_p:IPPROTO_TCP, ip_ttl:0x40,
			ip_src: saddr);
tcp = forge_tcp_packet( ip: ip, th_sport: sport, th_dport: dport,
                          th_flags: TH_SYN, th_seq: rand(), th_ack: 0,
                          th_x2: 0, th_off: 5, th_win: 512, th_urp:0);

for (i = 0; i < 3; i ++)
{
  reply =  send_packet(pcap_active : TRUE, pcap_filter : filter,
                        pcap_timeout:2, tcp);
  if (reply)
  {
    flags = get_tcp_element(tcp: reply, element: "th_flags");
    if ((flags & TH_SYN) && (flags & TH_ACK))
      security_note(port: 0); # Nessus API cannot really handle this
    exit(0);
  }
}

