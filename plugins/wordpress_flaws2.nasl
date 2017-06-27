#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15988);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/02/13 21:07:15 $");

  script_bugtraq_id(11984);
  script_osvdb_id(12617, 12618, 12619, 12620, 12621, 12622);

  script_name(english:"WordPress < 1.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
SQL injection and cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host has a version of WordPress
that is is vulnerable to various flaws which may allow an attacker to
perform an HTML injection attack against the remote host or allow an
attacker to execute arbitrary SQL statements against the remote
database.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/384659");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2004/12/one-point-two-two/");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 1.2.2 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

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

# Versions less than 1.2.2 are vulnerable
if (
  (ver[0] < 1) ||
  (ver[0] == 1 && ver[1] < 2) ||
  (ver[0] == 1 && ver[1] == 2 && ver[2] < 2)
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.2.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
