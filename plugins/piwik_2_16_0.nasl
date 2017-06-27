#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90537);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:13 $");

  script_osvdb_id(134025);

  script_name(english:"Piwik < 2.16.0 Unspecified XSS");
  script_summary(english:"Checks the version of Piwik.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Piwik running on the remote host is prior to 2.16.0.
It is, therefore, affected by an unspecified cross-site scripting
(XSS) vulnerability due to a failure to properly validate input before
returning it to users. An unauthenticated, remote attacker can exploit
this, via a crafted request, to execute arbitrary script code in a
user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://piwik.org/changelog/piwik-2-16-0/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Piwik version 2.16.0 or later. If necessary, remove any
affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piwik:piwik");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
fixed_ver = "2.16.0";

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir = install["dir"];
version = install["version"];
install_loc =  build_url(port:port, qs:dir);

if (version !~ "^([0-1]\..*|2\.([0-9]|[0-9][0-5])([^0-9]|$))")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc);

report  = 
  '\nThe following vulnerable instance of ' + appname + ' is installed' +
  '\non the remote host:' +
  '\n  URL               : ' + install_loc +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed_ver +
  '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
