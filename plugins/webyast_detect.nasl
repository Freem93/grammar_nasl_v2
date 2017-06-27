#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62966);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"WebYaST Web Client Detection");
  script_summary(english:"Looks for WebYaST web client interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An operating system management interface was detected on the remote web
server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"WebYaST web client, a web interface for YaST, was detected on the
remote host.  YaST is used for administration of hosts running SUSE
Linux operating systems."
  );
  script_set_attribute(attribute:"see_also", value:"http://webyast.github.com/webyast/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:suse:webyast");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 54984);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:54984);
dir = '';
page = '/bad_permissions.html';
res = http_send_recv3(method:'GET', item:dir + page, port:port, exit_on_fail:TRUE);

if ('# Webyast Webclient framework' >!< res[2])
  audit(AUDIT_WEB_FILES_NOT, 'WebYaST Web Client', port);

install = add_install(appname:'webyast_client', port:port, dir:dir);

if (report_verbosity > 0)
{
  report = get_install_report(installs:install, port:port, display_name:'WebYaST Web Client');
  security_note(port:port, extra:report);
}
else security_note(port);
