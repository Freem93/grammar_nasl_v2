#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11612);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_bugtraq_id(7129);
 script_osvdb_id(57160);

 script_name(english:"Intel PXE Server Remote Overflow");
 script_summary(english:"buffer overflow in PXE daemon");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running PXE (Preboot eXecution Environment), a
service which can be used to boot diskless clients.

There is a flaw in the remote PXE which may allow an attacker to gain
a root shell on this host.

*** Nessus disabled this service to perform this security check");
 script_set_attribute(attribute:"solution", value:"Upgrade or disable this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
# The strategy is to send an empty UDP packet and expect an ICMP-unreach message.
# If we don't get one, we crash the remote service and try again. If the results
# differ, then there was a service.
#

include("audit.inc");
include("global_settings.inc");


if ( TARGET_IS_IPV6 ) exit(0);
if (report_paranoia < 2) audit(AUDIT_PARANOID);


function check(dport)
{
 local_var filter, i, ippkt, res, sport, udppacket;

 sport = rand() % 65000 + 1024;
 ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :this_host()
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport:sport,
        uh_dport:dport,
        uh_ulen :8
        );

  filter = string("src host ", get_host_ip(), " and dst host ", this_host(),
 " and icmp and (icmp[0] == 3  and icmp[28:2]==", sport, ")");
  for(i=0;i<7;i++)
  {
  	res = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
	if( res != NULL ) return(1);
  }
  return(0);
}


if(check(dport:4011) == 0 )
{
  soc = open_sock_udp(4011);
  send(socket:soc, data:crap(4096));
  r = recv(socket:soc, length:4096);
  if(r)exit(0);

  close(soc);
  sleep(1);

  if(check(dport:4011) == 1)security_hole(port:4011, proto:"udp");
}
