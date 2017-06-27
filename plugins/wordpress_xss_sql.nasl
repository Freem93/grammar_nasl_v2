#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16023);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/02/02 14:39:40 $");

  script_cve_id("CVE-2004-1559");
  script_bugtraq_id(12066);
  script_osvdb_id(10410, 12617, 12621, 53612, 53613);

  script_name(english:"WordPress < 1.5.1 Multiple XSS and SQL Injection Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains multiple PHP scripts that are affected
by SQL injection and cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of WordPress is vulnerable
to a cross-site scripting attack that may allow an attacker to use the
remote server to steal the cookies of third-party users on the remote
site.

In addition, the remote version of this software is vulnerable to a
SQL injection attack that may allow an attacker to manipulate database
queries.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/385042");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 1.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

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

# Versions less than 1.5.1 are vulnerable
if (
  (ver[0] < 1) ||
  (ver[0] == 1 && ver[1] < 5) ||
  (ver[0] == 1 && ver[1] == 5 && ver[2] < 1)
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.5.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
