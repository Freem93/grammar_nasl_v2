#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56620);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_bugtraq_id(48521);
  script_osvdb_id(73722, 73723);

  script_name(english:"WordPress < 3.1.4 / 3.2-RC3 Multiple Blind SQL Injection Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application with multiple blind
SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of WordPress prior to 3.1.4 /
3.2-RC3. It is reportedly affected by multiple SQL injection
vulnerabilities due to a failure to adequately sanitize user-supplied
input prior to using it in database queries.");
   # http://wordpress.org/news/2011/06/wordpress-3-1-4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?298dd962");
  script_set_attribute(attribute:"solution", value:"Upgrade WordPress to version 3.1.4 or 3.2-RC3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 3 ||
  (
    ver[0] == 3 &&
    (
      ver[1] == 0 ||
      (ver[1] == 1 && (max_index(ver) == 2 || ver[2] < 4)) ||
      (ver[1] == 2 && (max_index(ver) == 2) && tolower(version) =~ "-(beta|rc[0-2]$)")
    )
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.1.4 / 3.2-RC3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
