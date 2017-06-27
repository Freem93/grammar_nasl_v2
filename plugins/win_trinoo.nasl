#
# (C) Tenable Network Security, Inc.
#


include( 'compat.inc' );

if(description)
{
	script_id(10307);
	script_version ("$Revision: 1.26 $");
	script_cvs_date("$Date: 2016/11/29 20:13:38 $");

	script_cve_id("CVE-2000-0138");
	script_osvdb_id(295);

	script_name(english:"Trin00 for Windows Trojan Detection");
	script_summary(english:"Detects the presence of trin00");

	script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is a malicious backdoor application.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote host appears to be running Trin00 for Windows, a trojan
that can be used to control your system or make it attack another
network (this is actually called a distributed denial of service
attack tool). 

It is very likely that this host has been compromised."
  );

  script_set_attribute(
    attribute:'solution',
    value:
"Restore your system from backups and contact CERT as well as your
local authorities."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(
    attribute:'see_also',
    value:'http://staff.washington.edu/dittrich/misc/trinoo.analysis'
  );


  script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/28");
  script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

	script_category(ACT_GATHER_INFO);

	script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc." );
	script_family(english:"Backdoors");
	script_require_keys("Settings/ThoroughTests");

	exit(0);
}

#
# The script code starts here
#


include('global_settings.inc');

if ( ! thorough_tests ) exit(1, "This plugin only runs if the 'Perform thorough tests' setting is enabled.");
if ( islocalhost() ) exit(0, "Can't check against localhost.");
if ( TARGET_IS_IPV6 ) exit(1, "This check is not implemented for IPv6 targets.");


command = string("png []..Ks l44");
die = string("d1e []..Ks l44");

ip  = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_UDP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

length = 8 + strlen(command);
udpip = forge_udp_packet(ip : ip,
		         uh_sport : 1024,
                         uh_dport : 34555,
			 uh_ulen : length,
			 data : command);

trg = get_host_ip();
me  = this_host();
pf = string("udp and src host ", trg, " and dst host ", me, " and dst port 35555");
rep = send_packet(udpip, pcap_filter:pf, pcap_active:TRUE);
if(rep)
{
  dstport = get_udp_element(udp:rep, element:"uh_dport");
  data = get_udp_element(udp:rep, element:"data");
  if(dstport == 35555 && "PONG" >< data)
  {
   security_hole(port:34555, protocol:"udp");
   length = 8 + strlen(die);
   udpip2 = forge_udp_packet(ip : ip,
		         uh_sport : 1024,
                         uh_dport : 34555,
			 uh_ulen : length,
			 data : die);
   send_packet(udpip2, pcap_active:FALSE);
   exit(0);
  }
}
exit(0, "The host does not appear to be affected.");
