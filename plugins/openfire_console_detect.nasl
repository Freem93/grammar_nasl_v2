#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51142);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"Openfire Admin Console Detection");
  script_summary(english:"Checks for the Openfire admin console login page");

  script_set_attribute(attribute:"synopsis", value:"An administration interface was detected on the remote web server.");
  script_set_attribute(attribute:"description", value:
"An Openfire admin console was detected on the remote host. Openfire is
a collaboration server based on the XMPP (Jabber) protocol.");
  script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/projects/openfire/index.jsp");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9090);
installs = NULL;

dir = '';
url = dir + '/login.jsp';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('<title>Openfire Admin Console</title>' >< res[2])
{
  pattern = 'Openfire, Version: ([0-9.]+)';
  match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
  if (match) ver = match[1];
  else ver = NULL;

  installs = add_install(
    installs:installs,
    dir:dir,
    ver:ver,
    appname:'openfire_console',
    port:port
  );
}

if (isnull(installs)) exit(0, 'An Openfire admin console wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Openfire Admin Console',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
