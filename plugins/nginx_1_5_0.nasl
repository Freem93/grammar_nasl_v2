#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66672);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2013-2028", "CVE-2013-2070");
  script_bugtraq_id(59699, 59824);
  script_osvdb_id(93037, 93282);
  script_xref(name:"EDB-ID", value:"25499");
  script_xref(name:"EDB-ID", value:"26737");
  script_xref(name:"EDB-ID", value:"32277");

  script_name(english:"nginx ngx_http_proxy_module.c Multiple Vulnerabilities");
  script_summary(english:"Checks version of nginx");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its Server response header, the installed version of nginx
is 1.3.x, greater than or equal to 1.3.9, or 1.4.x prior to 1.4.1.  It
is, therefore, affected by multiple vulnerabilities :

  - A stack-based buffer overflow in 'ngx_http_parse.c' may
    allow a remote attacker to execute arbitrary code or
    trigger a denial of service condition via a specially
    crafted HTTP request. This vulnerability only affects
    versions greater than or equal to 1.3.9 and less than
    1.4.1. (CVE-2013-2028)

  - A memory disclosure vulnerability in 'ngx_http_parse.c'
    affects servers that use 'proxy_pass' to untrusted
    upstream servers.  This issue can be triggered by a
    remote attacker via a specially crafted HTTP request.
    Failed attempts may result in a denial of service
    condition. (CVE-2013-2070)"
  );
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000112.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000114.html");
  script_set_attribute(attribute:"solution", value:
"Either apply the patch manually or upgrade to nginx 1.4.1 / 1.5.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/nginx");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, "The web server listening on port "+port+" does not send a Server response header.");
if ("nginx" >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, "nginx");

vpieces = eregmatch(string: server_header, pattern:"^nginx\/(.*)$");
if (isnull(vpieces)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "nginx", port);
version = vpieces[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^1(\.3)?$" || version =~ "^1(\.4)?$")
  exit(1, "The version ("+version+") of the nginx server listening on port "+port+" is not granular enough.");

# Affected: 1.3.0 - 1.4.0
if (
  version =~ "^1\.3\.([0-9]|[1-9][0-9])([^0-9]|$)" ||
  version =~ "^1\.4\.0([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.1 / 1.5.0' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
