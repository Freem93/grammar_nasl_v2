#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62118);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/27 13:33:27 $");

  script_cve_id("CVE-2012-2577", "CVE-2012-2602");
  script_bugtraq_id(54624);
  script_osvdb_id(84116, 84117);
  script_xref(name:"CERT", value:"174119");
  script_xref(name:"EDB-ID", value:"20011");

  script_name(english:"SolarWinds Orion NPM < 10.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of SolarWinds Orion NPM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of SolarWinds Orion NPM prior to
10.3.1. It is, therefore, affected by the following vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist that
    allow arbitrary web scripts to be injected via the
    'syslocation', 'syscontact', or 'sysName' fields of an
    'snmpd.conf' file. (CVE-2012-2577)

  - Multiple cross-site request forgery vulnerabilities
    exist that allow remote attackers to hijack the
    authentication of administrators for requests to
    create user accounts or modify their privileges via
    the 'CreateUserStepContainer' or 'ynAdminRights'
    actions to 'OrionAccount.aspx' or 'EditAccount.aspx'
    respectively. (CVE-2012-2602)

  - An unspecified SQL injection vulnerability exists.");
  # http://www.solarwinds.com/documentation/Orion/docs/ReleaseNotes/releaseNotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea627d5d");
  script_set_attribute(attribute:"solution", value:"Upgrade to SolarWinds Orion NPM 10.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_performance_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8787);
  script_dependencies("solarwinds_orion_npm_detect.nasl");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8787);

app = "SolarWinds Orion Core";

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(
  app_name  : app,
  port      : port
);

appname = "SolarWinds Orion Network Performance Monitor";

dir = install['path'];
install_loc = build_url(port:port, qs:dir+"/Login.aspx");

version = install['NPM Version'];

if (isnull(version)) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_loc);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 10.3.1 are vulnerable
if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 3) ||
  (ver[0] == 10 && ver[1] == 3 && ver[2] < 1)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 10.3.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc, version);
