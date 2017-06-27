#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53208);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"Symantec LiveUpdate Administrator Web Detection");
  script_summary(english:"Looks for the About page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The console for an update management application was detected on the
remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Symantec LiveUpdate Administrator (LUA) was detected on the remote
host.  LUA provides centralized management for multiple internal
LiveUpdate servers."
  );
  # http://www.symantec.com/connect/articles/installation-and-configuration-lua
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d69f033");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:liveupdate_administrator");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7070, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:7070);
dir = '/lua';
url = dir + '/pages/message/About.jsp';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('Symantec Corporation. All rights reserved.' >!< res[2])
  exit(0, 'Symantec LUA doesn\'t appear to be on port '+port+'.');

match = eregmatch(string:res[2], pattern:'Version: ([0-9.]+)');
if (isnull(match)) exit(1, 'Failed to find a version in the response from port '+port+'.');
ver = match[1];

debug_url = dir + '/' + unixtime() + '.debug';
res = http_send_recv3(method:'GET', item:debug_url, port:port, exit_on_fail:TRUE);
if (
  'LUA THREAD DUMP' >!< res[2] ||
  'com.symantec.lua' >!< res[2]
) exit(1, 'The response to the debug request on port '+port+' doesn\'t look like LUA.');

install = add_install(dir:dir, ver:ver, appname:'symantec_lua', port:port);
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Symantec LiveUpdate Administrator',
    installs:install,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
