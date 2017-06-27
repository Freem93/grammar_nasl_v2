#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{

  script_id(57617);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/03/03 18:58:53 $");

script_cve_id("CVE-2010-2544", "CVE-2010-2545");
  script_bugtraq_id(42575);
  script_osvdb_id(
    67412,
    67505,
    67506,
    67507,
    67508,
    67509,
    67510,
    67511,
    67512,
    67513,
    67514,
    67515,
    67516,
    67517,
    67518,
    67519,
    67520,
    67521,
    67522,
    67523,
    67524,
    67525,
    67526,
    67527,
    67528,
    67529
  );

  script_name(english:"Cacti < 0.8.7g Multiple XSS and HTML Injection Vulnerabilities");
  script_summary(english:"Checks the version of Cacti.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple cross-site scripting and HTML injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cacti application
running on the remote web server is prior to version 0.8.7g. It is,
therefore, potentially affected by multiple cross-site scripting and
HTML injection vulnerabilities. An attacker may be able to exploit
these issues to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site.");
  script_set_attribute(attribute:"see_also", value:"http://cacti.net/release_notes_0_8_7g.php");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=oss-security&m=127978954522586");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.7g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/cacti", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'cacti';
get_install_count(app_name:'cacti', exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
cacti_base = build_url(qs:install['path'], port:port);
version = install['version'];

# Versions < 0.8.7g are affected.
ver = split(version, sep:'.', keep:FALSE);
if (
  (int(ver[0]) == 0) &&
  (
   (int(ver[1]) < 8) ||
   (int(ver[1]) == 8 && ver[2] =~ '^([0-6][a-z]?|7[a-f]?)$')
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =  '\n  URL               : ' + cacti_base +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 0.8.7g' +
              '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cacti", cacti_base, version);

