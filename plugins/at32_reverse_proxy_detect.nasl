#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58602);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"at32 Reverse Proxy Detection");
  script_summary(english:"Detects admin console for at32 Reverse Proxy");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a reverse proxy server.");
  script_set_attribute(
    attribute:"description",
    value:
"The admin console for the at32 Reverse Proxy software was detected on
the remote host. at32 Reverse Proxy allows you to host several
websites on a single IP or port."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.at32.com/doc/rproxy.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:at32:reverse_proxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8082);
  script_dependencies("http_version.nasl");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8082);

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("Server:" >< banner) exit(0, "The web server on port "+port+" sends a 'Server:' response header, unlike at32 Reverse Proxy.");

res = http_send_recv3(method:"GET", item:"/login", port:port, exit_on_fail:TRUE);

if ("<html><head><title>at32 Reverse Proxy - Login</title>" >!< res[2])
  exit(0, "at32 reverse proxy admin portal not found on port " + " port.");

item = eregmatch(pattern:"<B>at32 Reverse Proxy v([0-9][^<]+)</B>", string:res[2]);
if (isnull(item[1])) version = UNKNOWN;
else version = item[1];

installs = add_install(
  dir: "",
  ver: version,
  appname: 'at32_reverse_proxy',
  port: port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name: 'at32 Reverse Proxy',
    installs: installs,
    port: port
  );
  security_note(port: port, extra: report);
}
else security_note(port);
