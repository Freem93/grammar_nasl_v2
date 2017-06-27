#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58750);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2012-2089");
  script_bugtraq_id(52999);
  script_osvdb_id(81339);

  script_name(english:"nginx 1.0.7 - 1.0.14 / 1.1.3 - 1.1.18 ngx_http_mp4_module Buffer Overflow");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The web server on the remote host is affected by a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy. 

According to its Server response header, the installed version of
nginx is between 1.0.7 and 1.0.14 or 1.1.3 and 1.1.18 and is,
therefore, affected by a buffer overflow vulnerability. 

An error in the module 'ngx_http_mp4_module' can allow a specially
crafted mp4 file to cause a buffer overflow and can potentially allow
arbitrary code execution. 

Note that successful exploitation requires that the 'mp4'
configuration option is enabled and the module 'ngx_http_mp4_module'
is enabled. Nessus has not checked for either of these settings."
  );
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES-1.0");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.0.15 / 1.1.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/nginx");
  exit(0);
}


include("global_settings.inc");
include("audit.inc");
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

# Affected: 1.0.7-1.0.14, 1.1.3-1.1.18 
if (
  version =~ "^1\.0\.([7-9]|1[0-4])([^0-9]|$)" ||
  version =~ "^1\.1\.([3-9]|1[0-8])([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.0.15 / 1.1.19' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nginx", port, version);
