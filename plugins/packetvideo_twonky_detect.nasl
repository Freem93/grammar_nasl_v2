#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59241);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/05/23 20:27:08 $");

  script_name(english:"PacketVideo TwonkyServer Detection");
  script_summary(english:"Checks for presence of TwonkyServer");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is used for sharing music, photos, and
videos.");
  script_set_attribute(attribute:"description", value: 
"The remote web server is running PacketVideo TwonkyServer.  It is a
media server used for making available digital media, such as music,
photos, and videos.");
  script_set_attribute(attribute:"see_also", value:"http://www.twonky.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:packetvideo:twonky");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

#TwonkyServer uses port 9000
port = get_http_port(default:9000);

if (report_paranoia < 2)
{
  server_header = http_server_header(port:port);
  if (!server_header) audit(AUDIT_WEB_BANNER_NOT, port);
  if ("Twonky" >!< server_header) exit(0, "The web server listening on port "+ port +" is not TwonkyServer.");
}

dirs = cgi_dirs();
checks = make_array();

#rpc/get_all gives us version info
regexes = make_list();
regexes[0] = make_list("ininame=twonkyserver.ini");
regexes[1] = make_list("Version=([0-9\.]+)");
checks["/rpc/get_all"] = regexes;

#additional check
regexes = make_list();
regexes[0] = make_list("Twonky");
regexes[1] = make_list("Version: ([0-9\.]+)");
checks["/rpc/long_version"] = regexes;

installs = find_install(appname:"twonky", checks:checks, dirs:dirs, port:port);
if (isnull(installs))
  audit(AUDIT_NOT_LISTEN, "TwonkyServer", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name: "TwonkyServer",
    installs    : installs,
    port        : port
  );
}
security_note(port:port, extra:report);
