#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71117);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2013-4547");
  script_bugtraq_id(63814);
  script_osvdb_id(100015);

  script_name(english:"nginx < 1.4.4 / 1.5.7 ngx_parse_http Security Bypass");
  script_summary(english:"Checks version of nginx");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the Server response header,
the installed version of nginx is greater than 0.8.41 but prior to 1.4.4
/ 1.5.7.  It is, therefore, affected by a security bypass vulnerability
in 'ngx_http_parse.c' when a file with a space at the end of the URI is
requested.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000125.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.4");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Either apply the patch manually or upgrade to nginx 1.4.4 / 1.5.7 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/nginx");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/nginx");

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, "The web server listening on port "+port+" did not send a Server response header.");
if ("nginx" >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, "nginx");

vpieces = eregmatch(string: server_header, pattern:"^nginx\/(.*)$");
if (isnull(vpieces)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "nginx", port);
version = vpieces[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^1(\.4)?$" || version =~ "^1(\.5)?$")  audit(AUDIT_VER_NOT_GRANULAR, "nginx", port, version);

# Affected: 0.8.41 - 1.4.3, 1.5.0 - 1.5.6
if (
  version =~ "^1\.5\.[0-6]([^0-9]|$)" ||
  version =~ "^1\.4\.[0-3]([^0-9]|$)" ||
  version =~ "^1\.[0-3]\." ||
  version =~ "^0\.9\." ||
  version =~ "^0\.8\.([4][1-9]|[5-9][0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.4 / 1.5.7' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
