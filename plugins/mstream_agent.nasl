#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10390);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2017/02/16 21:23:30 $");
 script_cve_id("CVE-2000-0138");
 script_osvdb_id(295);

 script_name(english:"mstream DDoS Agent Detection");
 script_summary(english:"Detects the presence of a mstream agent");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a suspicious application installed.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a mstream agent, which is a
trojan that can be used to control your system or make it attack
another network (this is actually called a distributed denial of
service attack tool)

It is very likely that this host has been compromised");
 # http://web.archive.org/web/20010828115057/http://www.whitehats.com/info/IDS111
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?455cacb3");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95722093124322&w=2");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95715370208598&w=2");
 script_set_attribute(attribute:"solution", value:
"Restore your system from known good backups or re-install the
operating system.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#

include('global_settings.inc');
if ( TARGET_IS_IPV6 ) exit(0);
if ( islocalhost() ) exit(0);
if (!  thorough_tests ) exit(0);


function detect(dport, sport)
{
local_var command, dstport, filter, ip, len, r, udp;

command = string("ping\n");
ip  = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
		      ip_id:9, ip_tos:0, ip_p : IPPROTO_UDP,
		      ip_len : 20, ip_src : this_host(),
		     ip_ttl : 255);

len = 8 + strlen(command);
udp = forge_udp_packet( ip:ip,
			uh_sport:65535,
			uh_dport:dport,
			uh_ulen : len,
			data:command);

filter = string("udp and src host ", get_host_ip(), " and dst port ", sport, " and dst host ", this_host());

r = send_packet(udp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3);
if(!isnull(r))	{
	dstport = get_udp_element(udp:r, element:"uh_dport");
	if(dstport == sport)return(1);
	else return(0);
    }
else return(0);
}



if(detect(sport:6838, dport:10498))security_warning(port:10498, proto:"udp");
  else if(detect(sport:9325, dport:7983))security_warning(port:7983, proto:"udp");




