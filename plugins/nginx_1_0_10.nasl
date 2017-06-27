#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58413);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/26 01:40:12 $");

  script_cve_id("CVE-2011-4315");
  script_bugtraq_id(50710);
  script_osvdb_id(77184);

  script_name(english:"nginx < 1.0.10 ngx_resolver_copy Function DNS Response Parsing Buffer Overflow");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy.

According to its Server response header, the installed version of
nginx is earlier than 1.0.10 and is, therefore, affected by a
heap-based buffer overflow vulnerability.

An issue related to DNS response parsing exists in the function
'ngx_resolver_copy' in the file 'ngx_resolver.c' which can allow
remote attackers to cause a denial of service or possibly execute
arbitrary code.

Note that successful exploitation requires this application's custom
DNS resolver to be enabled and that this custom resolver is not
enabled by default.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES-1.0");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2011/11/17/8");
  script_set_attribute(attribute:"see_also", value:"http://trac.nginx.org/nginx/changeset/4268/nginx");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

if (version =~ "^1(\.0)?$") exit(1, "The version ("+version+") of the nginx server listening on port "+port+" is not granular enough to make a determination.");

# All < 1.0.10 are affected
if (
    version =~ "^0\." ||
    version =~ "^1\.0\.[0-9]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.0.10' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The nginx "+version+" install listening on port "+port+" is not affected.");
