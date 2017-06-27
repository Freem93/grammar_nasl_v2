
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
script_id(46222);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-1431", "CVE-2010-1644", "CVE-2010-2092");
  script_bugtraq_id(39653, 40149, 40332);
  script_osvdb_id(63967, 64964, 65014, 67369);
  script_xref(name:"Secunia", value:"39570");

  script_name(english:"Cacti < 0.8.7f Multiple Input Validation Vulnerabilities");
  script_summary(english:"Checks the version of Cacti.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"According to its self-reported version number, the Cacti application
running on the remote web server is prior to version 0.8.7f. It is,
therefore, potentially affected by the following vulnerabilities :

  - A vulnerability exists in 'templates_export.php' due to
    improper validation of input to the 'export_item_id'
    parameter. A remote attacker can exploit this to inject
    SQL queries to disclose arbitrary data. (CVE-2010-1431)

  - Cross-site scripting vulnerabilities exist related to
    the 'host_id' parameter of 'data_sources.php', or the
    'hostname' and 'description' parameters of 'host.php',
    which a remote attacker can exploit to inject arbitrary
    web script or HTML. (CVE-2010-1644)

  - A SQL injection vulnerability in 'graph.php' exists
    which can be exploited by a remote attacker using
    specially crafted GET requests to the 'rra_id' parameter
    which can cause a corresponding POST request or cookie
    to bypass proper validation. (CVE-2010-2092)");
  # http://www.bonsai-sec.com/en/research/vulnerabilities/cacti-os-command-injection-0105.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39e1a6fb");
  # http://www.php-security.org/2010/05/13/mops-2010-023-cacti-graph-viewer-sql-injection-vulnerability/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49d1a123");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/511393/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_7f.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.7f or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_require_keys("installed_sw/cacti", "Settings/ParanoidReport");
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
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
install_url = build_url(qs:install['path'], port:port);

# Versions < 0.8.7f are affected.
ver = split(install['version'], sep:'.', keep:FALSE);
if (
  (int(ver[0]) == 0) &&
  (
   (int(ver[1]) < 8) ||
   (int(ver[1]) == 8 && ver[2] =~ '^([0-6][a-z]?|7[a-e]?)$')
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =  '\n  URL               : ' + install_url +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 0.8.7e' +
              '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cacti", install_url, install['version']);
