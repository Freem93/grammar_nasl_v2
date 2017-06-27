#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17326);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2005-0353");
  script_bugtraq_id(12742);
  script_osvdb_id(14605);
  script_xref(name:"CERT", value:"108790");

  script_name(english:"Sentinel License Manager lservnt Service Remote Buffer Overflow");
  script_summary(english:"Detects remote buffer overflow vulnerability in Sentinel License Manager");

  script_set_attribute(attribute:"synopsis", value:"The remote service is subject to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sentinel License Manager that
is subject to remote buffer overflows.  By sending 3000 bytes or more to
the UDP port on which it listens (5093 by default), a remote attacker
can crash the LServnt.exe service, overwrite the EIP register, and
possibly execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.cirt.dk/advisories/cirt-30-advisory.pdf");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/123");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sentinel License Manager 8.0.0 or later as that reportedly
addresses the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SentinelLM UDP Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/sentinel-lm", 5093);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("Services/sentinel-lm");
if (!port) port = 5093;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

data = crap(data:"A", length:256);
send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);

if (!buf || (strlen(buf) != 256)) exit(0);

# if not Sentinel LM (allways the same reply)
if (!egrep(pattern:"^AAAAAAAAAAAA,PSH.*", string:buf)) exit(0);

# we try to crash it
# no safe checks as the only change is strcpy to strncpy and patched buffer is bigger
# 7.3 seems to be fixed

data = crap(data:"A", length:1400);
send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);

if (!buf) security_hole(port:port, proto:"udp");
