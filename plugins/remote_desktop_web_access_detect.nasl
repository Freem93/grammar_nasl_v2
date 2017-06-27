#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55800);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"Microsoft Remote Desktop Web Access Detection");
  script_summary(english:"Looks for the login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for an operating system deployment appliance was
detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Remote Desktop Web Access was detected on the remote web server.
This application allows access to RemoteApp and Desktop Connection via
a web browser."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc731923.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008:r2");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 443);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

# currently this app only runs on Windows 2008 R2 (IIS 7.5)
if (report_paranoia < 2)
{
  server = http_server_header(port:port);
  if (server != 'Microsoft-IIS/7.5')
    exit(0, 'The web server on port ' + port + ' doesn\'t look like IIS 7.5');
}

# the locale is in the URL of the login page, so rather than guess it we'll
# request the root dir and assume we'll get redirected
dir = '/RDWeb';
url = dir + '/Pages/default.aspx';
res = http_send_recv3(method:'GET', item:url, port:port, follow_redirect:2, exit_on_fail:TRUE);

if ('>RD Web Access</title>' >!< res[2])
  exit(0, 'RD Web Access doesn\'t appear to be on port ' + port);

install = add_install(
  appname:'rd_web_access',
  dir:dir,
  port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Remote Desktop Web Access',
    installs:install,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

