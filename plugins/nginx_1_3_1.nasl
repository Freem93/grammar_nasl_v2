#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61394);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/24 02:15:10 $");

  script_cve_id("CVE-2011-4963");
  script_osvdb_id(84339);
  script_bugtraq_id(55920);

  script_name(english:"nginx on Windows Directory Aliases Access Restriction Bypass");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The web server on the remote host may be affected by an access
restriction bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its Server response header, the installed version of
nginx is 0.x greater than or equal to 0.7.52 or 1.x earlier than 1.2.1
/ 1.3.1 and is, therefore, affected by an access restriction bypass
vulnerability. 

By using a request with a specially crafted directory name, such as
'/directory::$index_allocation' in place of '/directory', an attacker
may be able to bypass access restrictions such as :

    location /directory/ {
        deny all;
    }

Note that this vulnerability only affects installs on Windows and that
Nessus has not tried to verify the underlying OS."
  );
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.2");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.1 / 1.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/02");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
if (isnull(server_header)) exit(0, "The web server listening on port "+port+" does not send a Server response header.");
if ("nginx" >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, "nginx");

vpieces = eregmatch(string: server_header, pattern:"^nginx\/(.*)$");
if (isnull(vpieces)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "nginx", port);

version = vpieces[1];

if ((version =~ "^0(\.7)?$") || (version =~ "^1(\.2)?$") || (version =~ "^1(\.3)?$"))
  exit(1, "The version ("+version+") of the nginx server listening on port "+port+" is not granular enough.");

# Affected: 0.7.52 - 1.2.0 / 1.3.0
# Not aware of 0.x versions like 0.10.x
if (
  (version =~ "^0\.7\.(5[2-9]|[6-9][0-9])([^0-9]|$)") ||
  (version =~ "^0\.[89]([^0-9]|$)") ||
  (version =~ "^1\.[01]([^0-9]|$)") ||
  (version =~ "^1\.2\.0([^0-9]|$)") ||
  (version =~ "^1\.3\.0([^0-9]|$)")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.2.1 / 1.3.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nginx", port, version);
