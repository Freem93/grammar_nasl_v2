#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42801);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_bugtraq_id(37005, 37014);
  script_osvdb_id(59958, 59959);
  script_xref(name:"Secunia", value:"37332");

  script_name(english:"WordPress < 2.8.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the installation of WordPress is
affected by multiple vulnerabilities :

  - It is possible for an attacker with valid credentials to
    upload arbitrary files, resulting in arbitrary code
    execution.

  - A cross-site scripting vulnerability exists in
    'Press-This'.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5090570");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507819/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 2.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions < 2.8.6 are affected.
if (
  ver[0] < 2 ||
  (
    ver[0] == 2 &&
    (
      ver[1] < 8 ||
      (
        ver[1] == 8 &&
        (
          max_index(ver) == 2 ||
          ver[2] < 6
        )
      )
    )
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      "\n" +
      "Nessus found the following vulnerable WordPress install :\n" +
      "\n" +
      "  URL               :" + install_url + "\n" +
      "  Installed version : "+ version + "\n" +
      "  Fixed version     : 2.8.6\n";
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
