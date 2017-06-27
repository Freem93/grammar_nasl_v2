#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62893);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/27 13:33:27 $");

  script_bugtraq_id(54082);
  script_osvdb_id(83510);

  script_name(english:"SolarWinds Orion NPM < 9.5 Login.asp SQLi");
  script_summary(english:"Checks for the deprecated Login.asp script.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of SolarWinds Orion NPM that has
a deprecated 'Login.asp' script that is accessible and contains a
blind SQL injection vulnerability.");
  # https://web.archive.org/web/20120801224719/http://www.digitaldefense.net/resources/vulnerability-research-team-advisories.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92962ce8");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to SolarWinds 9.5 or later, or delete the deprecated
'Login.asp' script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/12");

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

# Upgrades >= 9.5 are said to remove the vulnerable file
if (
  ver[0] < 9 ||
  (ver[0] == 9 && ver[1] < 5)
)
{
  # see if vulnerable script has been removed
  res = http_send_recv3(port:port,
                        method:"GET",
                        item:dir+"/Login.asp",
                        exit_on_fail:TRUE);

  # make sure affected script is actually accessible on host and hasn't been removed
  if (
    '200' >< res[0] &&
    'Location: /Orion/Login.aspx' >!< res[1] &&
    'Object Moved' >!< res[2]
  )
  {
    set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

    if (report_verbosity > 0)
    {
      report = '\nAccording to the version of SolarWinds Orion NPM installed, the' +
               '\nfollowing script is affected by a blind SQL injection vulnerability :\n' +
               '\n  URL               : ' + build_url(qs:dir + "/Login.asp", port:port) +
               '\n  Installed version : ' + version +
               '\n  Fixed version     : 9.5' +
               '\n';

      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
  else exit(0, 'Login.asp was not found on the remote host.');
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc, version);
