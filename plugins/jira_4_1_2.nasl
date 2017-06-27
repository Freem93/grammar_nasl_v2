#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47114);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/08/04 14:48:27 $");

  script_bugtraq_id(40950, 40953);
  script_xref(name:"Secunia", value:"40212");

  script_name(english:"Atlassian JIRA 4.1.x < 4.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is 4.1.x prior to
4.1.2. It is, therefore, potentially affected by multiple
vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exit
    involving the URL query string passed to unspecified
    scripts.

  - In the standalone distribution, cookies are not stored
    with the 'HttpOnly' option set.

  - Users without 'JIRA Users' permission can login via
    crowd single sign on.

  - There is a cross-site request forgery vulnerability
    involving the 'Logout' action.

  - Unspecified vulnerabilities exists related to Bamboo and
    and FishEye when these plugins are enabled in JIRA.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2010-06-18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28b67183");
  script_set_attribute(attribute:"solution", value:"Upgrade to Atlassian JIRA 4.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);

fix = "4.1.2";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
exit(0);
