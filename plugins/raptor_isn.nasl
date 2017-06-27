#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive
#

include("compat.inc");

if(description)
{
 script_id(11057);
 script_version("$Revision: 1.33 $");

 script_cve_id("CVE-2002-1463");
 script_bugtraq_id(5387, 8652);
 script_osvdb_id(199);

 script_name(english:"TCP/IP Initial Sequence Number (ISN) Reuse Weakness");

 script_set_attribute(attribute:"synopsis", value:
"The remote device seems to generate predictable TCP Initial Sequence
Numbers." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to generate Initial Sequence Numbers (ISN) in a weak
manner which seems to solely depend on the source and dest port of the TCP 
packets.

An attacker may exploit this flaw to establish spoofed connections to the 
remote host.

The Raptor Firewall and Novell NetWare are known to be vulnerable to this 
flaw, although other network devices may be vulnerable as well." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2002/Aug/60"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://securityresponse.symantec.com/avcenter/security/Content/2002.08.05.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:
"If you are using a Raptor Firewall, install the TCP security hotfix
described in Symantec's advisory.  Otherwise, contact your vendor for
a patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/01/01");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"checks for ISN");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

include('global_settings.inc');
if ( ! thorough_tests ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);
if(islocalhost())exit(0);

 port = get_host_open_port();
 if(!port)exit(0);

  ip1 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :rand(),
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :this_host()
        );


  ip2 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :rand(),
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :this_host()
        );
	
  s1 = rand();
  s2 = rand();	
  tcp1 = forge_tcp_packet(ip:ip1,
                               th_sport: 1500,
                               th_dport: port,
                               th_flags:TH_SYN,
                               th_seq: s1,
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 8192,
                               th_urp: 0);
			       
			       
 tcp2 = forge_tcp_packet(ip:ip1,
                               th_sport: 1500,
                               th_dport: port,
                               th_flags:TH_SYN,
                               th_seq: s2,
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 0,
                               th_urp: 0);			       
s1 = s1 + 1;
s2 = s2 + 1;

filter = string("tcp and src " , get_host_ip() , " and dst port ", 1500);
r1 = send_packet(tcp1, pcap_active:TRUE, pcap_filter:filter);

if(r1)
{
  # Got a reply - extract the ISN
  isn1 = get_tcp_element(tcp:r1, element:"th_seq");
  ack1  = get_tcp_element(tcp:r1, element:"th_ack");
  if(!(ack1 == s1))exit(0);
  if(!isn1)exit(0); # port closed
  rst1 = forge_tcp_packet(ip:ip1,
  				th_sport:1500,
				th_dport: port,
				th_flags: TH_RST,
				th_seq: ack1,
				th_ack:0,
				th_x2: 0,
				th_off: 5,
				th_win: 0,
				th_urp: 0);
  send_packet(rst1, pcap_active:FALSE);			
  r2 = send_packet(tcp2, pcap_active:TRUE, pcap_filter:filter);
  if(r2)
  {
   # Send the second request
   isn2 = get_tcp_element(tcp:r2, element:"th_seq");
   ack2 = get_tcp_element(tcp:r2, element:"th_ack");
   if(!(ack2 == s2))exit(0);
   if(!isn2)exit(0); # port closed
  
   if(isn1 == isn2)security_hole(0);
  }
}
