#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66671);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/24 02:15:10 $");

  script_cve_id("CVE-2013-2070");
  script_bugtraq_id(59824);
  script_osvdb_id(93282);

  script_name(english:"nginx ngx_http_proxy_module.c Memory Disclosure");
  script_summary(english:"Checks version of nginx");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by a remote memory disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its Server response header, the installed version of nginx
is 1.1.x, greater than or equal to 1.1.4, or 1.2.x prior to 1.2.9.  It
is, therefore, affected by a memory disclosure vulnerability in
'ngx_http_proxy_module.c' when 'proxy_pass' to untrusted upstream
servers is used. 

By sending a specially crafted request, an attacker may be able to gain
access to worker process memory or trigger a denial of service
condition."
  );
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000114.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:"Either apply the patch manually or upgrade to nginx 1.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

if (version =~ "^1(\.1)?$" || version =~ "^1(\.2)?$")
  exit(1, "The version ("+version+") of the nginx server listening on port "+port+" is not granular enough.");

# Affected: 1.1.4 - 1.2.8
if (
  version =~ "^1\.1\.([4-9]|[1-9][0-9])([^0-9]|$)" ||
  version =~ "^1\.2\.[0-8]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.2.9' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "nginx", port, version);
