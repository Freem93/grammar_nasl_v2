#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10350);
 script_version ("$Revision: 1.25 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");

 script_cve_id("CVE-2000-0138");
 script_osvdb_id(295);
 
 script_name(english: "Shaft Trojan Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a Trojan horse." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Shaft, which is a trojan that can 
be used to control your system or make it attack another network (this 
is actually called a distributed denial of service attack tool).

It is very likely that this host has been compromised" );
 script_set_attribute(attribute:"solution", value:
"Restore your system from backups, contact CERT and your local authorities." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/03/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Detects the presence of Shaft");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#


include('global_settings.inc');

if ( islocalhost() ) exit(0);
if ( ! thorough_tests ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

shaft_dstport = 18753;
shaft_rctport = 20433;
shaft_scmd = "alive";
shaft_spass = "tijgu";



command = string(shaft_scmd, " ", shaft_spass, " hi 5 1918");


ip  = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_UDP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);
		   
length = 8 + strlen(command);		     
udpip = forge_udp_packet(ip : ip,
		         uh_sport : 1024,    
                         uh_dport : shaft_dstport,
			 uh_ulen : length,
			 data : command);
			 
filter = string("udp and src host ", get_host_ip(), " and dst host ", this_host(), " and dst port ", shaft_rctport);		 
rep = send_packet(udpip, pcap_filter:filter, pcap_active:TRUE);		
	 	
if(!isnull(rep))
{
 dstport = get_udp_element(udp:rep, element:"uh_dport");
 if(dstport == shaft_rctport && "alive tijgu" >< rep )security_hole(port:shaft_dstport, protocol:"udp");
}
