#
# (C) Tenable Network Security, Inc.
#

#
# Problem: This check is prone to false negatives (if the remote FW
#          does not allow outgoing icmp-unreach packets [default on kerio]).
#	   However I've decided to include this plugin anyway as it might
#	   uncover issues in other firewalls.
#

include("compat.inc");

if (description)
{
  script_id(11580);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2003-1491", "CVE-2004-1473");
  script_bugtraq_id(7436, 11237);
  script_osvdb_id(10205, 60212);

  script_name(english:"Firewall UDP Packet Source Port 53 Ruleset Bypass");
  script_summary(english:"By-passes the remote firewall rules");

  script_set_attribute(attribute:"synopsis", value:"Firewall rulesets can be bypassed.");
  script_set_attribute(attribute:"description", value:
"It is possible to bypass the rules of the remote firewall by sending
UDP packets with a source port equal to 53.

An attacker may use this flaw to inject UDP packets to the remote
hosts, in spite of the presence of a firewall.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Apr/355");
  # http://securityresponse.symantec.com/avcenter/security/Content/2004.09.22.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4368bb37");
  script_set_attribute(attribute:"solution", value:
"Either contact the vendor for an update or review the firewall rules
settings.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kerio:personal_firewall");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0, "This script only runs in IPv4.");

if ( islocalhost() ) exit(0, "This script cannot be run on localhost.");

function check(sport)
{
 local_var filter, i, ippkt, res, udppacket;

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
        uh_dport:1026,
        uh_ulen :8
        );

  filter = string("src host ", get_host_ip(), " and dst host ", this_host(),
 " and icmp and (icmp[0] == 3  and icmp[28:2]==", sport, ")");
  for(i=0;i<3;i++)
  	{
  	res = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3);
	if(!isnull(res))return(1);
	}
 return(0);
}

if(check(sport:1025) == 1)
{
 exit(0);
}

if(check(sport:53) == 1)
{
 security_hole(proto:"udp", port:0);
}
