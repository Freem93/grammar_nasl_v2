#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24813);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/26 01:15:51 $");

  script_cve_id("CVE-2007-0774");
  script_bugtraq_id(22791);
  script_osvdb_id(33855);

  script_name(english:"Apache mod_jk Long URL Worker Map Stack Remote Overflow");
  script_summary(english:"Checks version of mod_jk");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server includes a module that is affected by an
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Apache mod_jk module in
use on the remote web server contains a buffer overflow vulnerability.
An unauthenticated, remote attacker may be able to exploit this flaw
by sending a long URL request to crash the affected service or execute
arbitrary code on the remote host, subject to the privileges of the
web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-008.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/461734/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat Connector 1.2.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_jk 1.2.20 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# Do a banner check.
banner = get_http_banner(port:port);
if (banner)
{
  server = strstr(banner, "Server:");
  if (server) server = server - strstr(server, string("\n"));
  if (
    server &&
    # nb: advisory states only 1.2.19 and 1.2.20 were affected.
    ereg(pattern:".*mod_jk/1\.2\.(19|20)([^0-9]|$)", string:server)
  ) security_hole(port);
}
