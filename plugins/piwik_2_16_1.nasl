#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90538);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(
    136583,
    136584,
    136585
  );

  script_name(english:"Piwik < 2.16.1-rc1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Piwik.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Piwik running on the remote web host is prior to
version 2.16.1-rc1. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists that may allow an attacker to
    have a critical impact. No further details are
    available. (VulnDB 136583)

  - Multiple unspecified cross-site scripting (XSS)
    vulnerabilities exist due to a failure to properly
    validate input before returning it to users. An
    unauthenticated, remote attacker can exploit these, via
    a crafted request, to execute arbitrary script code in
    a user's browser session. (VulnDB 136584, VulnDB 136585)");
  script_set_attribute(attribute:"see_also", value:"http://piwik.org/changelog/piwik-2-16-1/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Piwik version 2.16.1-rc1 or later. If necessary, remove any
affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piwik:piwik");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("piwik_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Piwik", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Piwik";
fixed_ver = '2.16.1-rc1';

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir = install["dir"];
version = install["version"];
install_loc =  build_url(port:port, qs:dir);

if (version !~ "^([0-1]\..*|2\.(([0-9]|[0-1][0-5])([^0-9]|$)|16(\.0|\.1(\-([^r]|r[^c])|[^0-9\-$]))).*)$")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc);

report  = 
  '\nThe following vulnerable instance of ' + appname + ' is installed' +
  '\non the remote host:' +
  '\n  URL               : ' + install_loc +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed_ver +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE);
