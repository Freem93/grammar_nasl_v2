#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10522);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2000-0917");
 script_bugtraq_id(1712);
 script_osvdb_id(421);
 script_xref(name:"CERT", value:"382365");

 script_name(english:"LPRng use_syslog() Remote Format String Arbitrary Command Execution");
 script_summary(english:"Checks for a vulnerable version of LPRng");

 script_set_attribute(attribute:"synopsis", value:"The remote print service is affected by format string vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"LPRng seems to be running on this port.

Versions of LPRng prior to 3.6.24 are missing format string arguments
in at least two calls to 'syslog()' that handle user-supplied input.

Using specially crafted input with format strings, an unauthenticated,
remote attacker may be able to leverage these issues to execute
arbitrary code subject to the privileges under which the service
operates, typically 'root'.

Note that Nessus has not determined that the remote installation of
LPRng is vulnerable, only that it is listening on this port.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Sep/432");
 script_set_attribute(attribute:"solution", value:"Upgrade, if necessary, to LPRng version 3.6.25.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'LPRng use_syslog Remote Format String Vulnerability');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/10/01");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:caldera:openlinux_ebuilder");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(515);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_port_state(515))
{
soc = open_sock_tcp(515);
if(soc)
{
 snd = raw_string(9)+ string("lp") + raw_string(0x0A);

 send(socket:soc, data:snd);
 r = recv(socket:soc, length:1024);
 if("SPOOLCONTROL" >< r)
 {
  security_hole(515);
 }
}
}
