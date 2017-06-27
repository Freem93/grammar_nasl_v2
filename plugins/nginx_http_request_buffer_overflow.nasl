#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41608);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2009-2629", "CVE-2009-3896");
  script_bugtraq_id(36384, 36839);
  script_osvdb_id(58128, 59278);
  script_xref(name:"CERT", value:"180065");

  script_name(english:"nginx HTTP Request Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy.

According to its Server response header, the installed version of
nginx is affected by multiple vulnerabilities : - A remote buffer
overflow attack related to its parsing of complex URIs.

  - A remote denial of service attack related to its parsing
    of HTTP request headers.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES-0.7");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES-0.6");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES-0.5");
  script_set_attribute(attribute:"see_also", value:"http://sysoev.ru/nginx/patch.180065.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Oct/306");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.8.15, 0.7.62, 0.6.39, 0.5.38, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
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

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0,"The web server listening on port " + port + " does not send a Server response header.");
if ("nginx" >!< tolower(server_header)) exit(0, "The web server on port "+port+" does not appear to be nginx.");

match = eregmatch(string: server_header, pattern:"^nginx\/(.*)$");
if (isnull(match)) exit(1, "Failed to extract the version of the nginx server listening on port "+port+".");
version = match[1];

pat = "^0\.(5\.([0-9]|[1-2][0-9]|3[0-7])|" +
           "6\.([0-9]|[1-2][0-9]|3[0-8])|" +
           "7\.([0-9]|[1-5][0-9]|6[0-1])|" +
           "8\.([0-9]|1[0-4]))" +
           "([^0-9]|$)" ;

if (egrep(pattern:pat, string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.8.15 / 0.7.62 / 0.6.39 / 0.5.38' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
