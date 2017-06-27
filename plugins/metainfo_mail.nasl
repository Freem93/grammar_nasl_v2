#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID

include("compat.inc");

if (description)
{
 script_id(10141);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-1999-0268");
 script_bugtraq_id(110);
 script_osvdb_id(110, 3969);

 script_name(english:"MetaInfo Web Server Traversal Arbitrary Command Execution");
 script_summary(english:"Read everything using '../' in the URL");

 script_set_attribute(attribute:"synopsis", value:"The remote host has a command execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote MetaInfo web server (installed with MetaInfo's Sendmail or
MetaIP servers) has an arbitrary command execution vulnerability. It
is possible to read files or execute arbitrary commands by prepending
the appropriate number of '../' to the desired filename. A remote
attacker could exploit this to execute arbitrary commands on the
system.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1998/Jun/235");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/06/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(5000);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 5000;

if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:"../smusers.txt", port:port, exit_on_fail: TRUE);

  rep = res[0] + res[1] + res[2];
  if(" 200 " >< rep)security_hole(port);
}
