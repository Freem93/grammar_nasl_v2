#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59834);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Symantec Message Filter Management Interface Detection");
  script_summary(english:"Looks for BCC login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web management interface for an email filtering application is
hosted on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Brightmail Control Center, the management interface for Symantec
Message Filter, was detected on the remote host.  Symantec Message
Filter is used to filter email for issues such as spam, viruses, and
phishing attacks."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.symantec.com/message-filter");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/03");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:message_filter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 41080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:41080);
dir = '/brightmail';
page = '/viewLogin.do';
res = http_send_recv3(method:'GET', item:dir + page, port:port, exit_on_fail:TRUE);

if (
  '<title>Symantec Message Filter -Login</title>' >!< res[2] &&
  '<title>Symantec Brightmail AntiSpam' >!< res[2] &&
  '<title>Symantec Brightmail Message Filter' >!< res[2]
)
{
  audit(AUDIT_WEB_FILES_NOT, 'Symantec Message Filter', port);
}

# try to get the version if possible
res = http_send_recv3(method:'GET', item:dir + '/about.jsp', port:port);
match = eregmatch(string:res[2], pattern:"Version ([\d.]+)");
if (isnull(match))
  version = NULL;
else
  version = match[1];

install = add_install(appname:'smf_bcc', ver:version, dir:dir, port:port);

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Symantec Message Filter', installs:install, item:page, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);
