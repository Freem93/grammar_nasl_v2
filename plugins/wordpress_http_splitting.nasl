#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15443);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_cve_id("CVE-2004-1584");
  script_bugtraq_id(11348);
  script_osvdb_id(10595);

  script_name(english:"WordPress 'wp-login.php' HTTP Response Splitting");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
HTTP splitting attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of WordPress is vulnerable
to an HTTP-splitting attack wherein an attacker can insert CR LF
characters and then entice an unsuspecting user into accessing the
URL. The client will parse and possibly act on the secondary header
which was supplied by the attacker.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/377770");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 1.2.1 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

  script_dependencie("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 1.2.1 are vulnerable
if (
  (ver[0] < 1) ||
  (ver[0] == 1 && ver[1] < 2) ||
  (ver[0] == 1 && ver[1] == 2 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.2.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "WordPress", install_url, version);
