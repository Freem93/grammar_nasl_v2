#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56820);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"Metasploit HTTP Server detection");
  script_summary(english:"Detects a Metasploit HTTP Server");

  script_set_attribute(attribute:"synopsis", value:"A Metasploit HTTP server is listening on the remote port.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a Metasploit HTTP server, which is used
for performing a variety of security scanning and exploitation
attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/products/penetration-testing.jsp");
  script_set_attribute(attribute:"solution", value:"Disable this service if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 3790);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:3790);

url = '/login';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

pattern = 'Please enable Javascript before using Metasploit';
match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
if (!match) exit(0, "Metasploit wasn't detected on the web server on port " + port + ".");

installs = add_install(
  dir      : '/login',
  appname  : 'metasploit',
  port     : port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Metasploit',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
