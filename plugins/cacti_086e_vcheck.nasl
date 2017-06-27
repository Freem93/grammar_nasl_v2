#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(81601);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/03 19:01:08 $");

  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526");
  script_bugtraq_id(14027, 14028, 14030, 14042, 14128, 14129);
  script_osvdb_id(17424, 17425, 17426, 17539);

  script_name(english:"Cacti < 0.8.6e Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cacti.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cacti application
running on the remote web server is prior to version 0.8.6e. It is,
therefore, potentially affected by the following vulnerabilities :

  - A PHP file inclusion vulnerability exists in
    'top_graph_header.php' that allows remote attackers to
    execute arbitrary PHP code using the
    'config[library_path]' parameter. (CVE-2005-1524)

  - A SQLi vulnerability exists in 'config_settings.php'
    that allows remote attackers to execute arbitrary SQL
    commands using the 'id' parameter. (CVE-2005-1525)

  - A PHP remote file inclusion vulnerability exists in
    'config_settings.php' that allows remote attackers to
    execute arbitrary PHP code using the
    'config[include_path]' parameter. (CVE-2005-1526)");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_6e.php");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403174/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.6e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti graph_view.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/cacti", "www/PHP", "Settings/ParanoidReport");
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

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

install_url = build_url(qs:install['path'], port:port);
version = install['version'];

ver = split(version, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
   int(ver[1]) < 8 ||
   (int(ver[1]) == 8 && ver[2] =~ '^([0-5][a-z]?|6[a-d]?)$')
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =  '\n  URL               : ' + install_url +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 0.8.6e' +
              '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cacti", install_url, version);
