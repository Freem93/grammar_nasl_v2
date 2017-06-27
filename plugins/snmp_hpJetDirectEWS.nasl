#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11317);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-2002-1048");
 script_bugtraq_id(5331, 7001);
 script_osvdb_id(2079);

 script_name(english:"HP JetDirect Device SNMP Request Cleartext Admin Credential Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The administrative password of the remote HP JetDirect printer can be obtained
using SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the password of the remote HP JetDirect
web server by sending SNMP requests.

An attacker may use this information to gain administrative access
to the remote printer." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port.

http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/27");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Enumerates password of JetDirect Web Server via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/OID", "SNMP/community");
 exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");


oid = get_kb_item("SNMP/OID");
if (!oid)
  exit (0);

# exit if not HP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.11", oid:oid))
  exit (0);


community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

pass = snmp_request_next (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.3.9.1.1.13");
if (isnull(pass) || (pass[0] != "1.3.6.1.4.1.11.2.3.9.1.1.13.0"))
  exit (0);

hexpass = hexstr(pass[1]);
if (hexpass == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") exit(0);

if (strlen(pass[1]) <= 0 || pass[1] =~ "^ *$" )
  exit(0);
else
  password = string ("Remote printer password is : ",pass[1]);

security_hole(port:port, extra: password, protocol:"udp");
