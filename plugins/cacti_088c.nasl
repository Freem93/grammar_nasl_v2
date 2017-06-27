#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81603);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/03/30 15:16:51 $");

  script_cve_id(
    "CVE-2013-5588",
    "CVE-2013-5589",
    "CVE-2014-2326",
    "CVE-2014-2327",
    "CVE-2014-2328",
    "CVE-2014-2708",
    "CVE-2014-2709",
    "CVE-2014-4002",
    "CVE-2014-5025",
    "CVE-2014-5026"
  );
  script_bugtraq_id(
    62001,
    62005,
    66387,
    66390,
    66392,
    66555,
    66630,
    68257,
    68759
  );
  script_osvdb_id(
    96600,
    96601,
    96602,
    104909,
    104921,
    104922,
    105246,
    108492,
    108493,
    108494,
    108495,
    108496,
    108497,
    108498,
    108499,
    108500,
    109364,
    109365,
    109366,
    109367,
    109368,
    109369,
    109370
  );

  script_name(english:"Cacti < 0.8.8c Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cacti.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cacti application
running on the remote web server is prior to version 0.8.8c. It is,
therefore, potentially affected by the following vulnerabilities :

  - Multiple XSS vulnerabilities exist in the 'step'
    parameter to 'install/index.php' and the 'id'
    parameter in 'cacti/host.php'. (CVE-2013-5588)

  - A SQL injection vulnerability in the 'id' parameter to
    'cacti/host.php' could allow remote attackers to inject
    arbitrary SQL commands. (CVE-2013-5589)

  - An XSS vulnerability exists via unspecified vectors to
    'cdef.php'. (CVE-2014-2326)

  - A XSRF vulnerability exists that allows remote attackers
    to hijack the authentication of users for unspecified
    commands. (CVE-2014-2327)

  - A flaw exists in 'lib/graph_export.php' that allows
    remote authenticated users to execute arbitrary commands
    via shell metacharacters in unspecified vectors.
    (CVE-2014-2328)

  - Multiple SQL injection vulnerabilities exist in
    'graph_xport.php' which allow remote attackers to inject
    arbitrary SQL commands.  (CVE-2014-2708)

  - Improper escaping of shell metacharacters in unspecified
    parameters allows remote attackers to execute arbitrary
    commands. (CVE-2014-2709)

  - Multiple XSS vulnerabilities exist that allow attackers
    to inject arbitrary script data using the 'drp_action',
    'graph_template_input_id', and 'graph_template_id'
    parameters to various PHP scripts. (CVE-2014-4002)

  - A XSS vulnerability exists in 'data_sources.php' which
    allows a remote, authenticated user with console access
    to inject arbitrary script data via the 'name_cache'
    parameter in a ds_edit action. (CVE-2014-5025)

  - Multiple XSS vulnerabilities exists that allow attackers
    to inject arbitrary script data via 'Graph Tree Title',
    'CDEF Name', 'Data Input Method Name', 'Host Templates
    Name', 'Data Source Title', 'Graph Title', or 'Graph
    Template Name' when carried out under delete, edit, or
    duplicate actions. (CVE-2014-5026)");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_8c.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.8c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

install_url = build_url(qs:install['path'], port:port);
version = install['version'];

# Versions < 0.8.8c are affected.
ver = split(version, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
   int(ver[1]) < 8 ||
   (int(ver[1]) == 8 && ver[2] =~ '^([0-7][a-z]?|8[ab]?)$')
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report =  '\n  URL               : ' + install_url +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 0.8.8c' +
              '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cacti", install_url, version);
