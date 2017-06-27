#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69306);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/03 18:58:53 $");

  script_cve_id("CVE-2013-1434", "CVE-2013-1435");
  script_bugtraq_id(61657, 61847);
  script_osvdb_id(96071, 96072);

  script_name(english:"Cacti < 0.8.8b Command and SQL Injections");
  script_summary(english:"Checks the version of Cacti.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
command injection and SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cacti application
running on the remote web server is prior to version 0.8.8b. It is,
therefore, potentially affected by command injection and SQL injection
vulnerabilities because the application fails to properly sanitize
user-supplied input to various scripts. An attacker may be able to
exploit these issues to execute arbitrary code as well as access or
modify the underlying database for the application.");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_8b.php");
  script_set_attribute(attribute:"see_also", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/10816");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.8b or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/cacti", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'cacti';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

install_url = build_url(qs:install['path'], port:port);
version = install['version'];

# Versions < 0.8.8b are affected.
ver = split(version, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
   int(ver[1]) < 8 ||
   (int(ver[1]) == 8 && ver[2] =~ '^([0-7][a-z]?|8[a]?)$')
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =  '\n  URL               : ' + install_url +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 0.8.8b' +
              '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cacti", install_url, version);
