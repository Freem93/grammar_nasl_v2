#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58414);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2012-1180");
  script_bugtraq_id(52578);
  script_osvdb_id(80124);

  script_name(english:"nginx < 1.0.14 / 1.1.17 HTTP Header Response Memory Disclosure");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by a memory disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy.

According to its Server response header, the installed version of
nginx is earlier than 1.0.14 or is 1.1.x before 1.1.17 and is,
therefore, affected by a memory disclosure vulnerability.

An issue related to the parsing of HTTP header responses can allow a
remote attacker to obtain the contents of previously freed memory.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES-1.0");
  script_set_attribute(attribute:"see_also", value:"http://trac.nginx.org/nginx/changeset/4535/nginx");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.0.14 / 1.1.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport", "www/nginx");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0,"The web server listening on port " + port + " does not send a Server response header.");
if ("nginx" >!< tolower(server_header)) exit(0, "The web server on port "+port+" does not appear to be nginx.");

vpieces = eregmatch(string: server_header, pattern:"^nginx\/(.*)$");
if (isnull(vpieces)) exit(1, "Failed to extract the version of the nginx server listening on port "+port+".");

version = vpieces[1];

if (version =~ "^1(\.[01])?$") exit(1, "The version ("+version+") of the nginx server listening on port "+port+" is not granular enough.");

if (
    version =~ "^0\." ||
    version =~ "^1\.0\.([0-9]|1[0-3])([^0-9]|$)" ||
    version =~ "^1\.1\.([0-9]|1[0-6])([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.0.14 / 1.1.17' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The nginx "+version+" install listening on port "+port+" is not affected.");
