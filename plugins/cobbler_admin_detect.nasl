#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(59400);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/06/07 13:23:28 $");

  script_name(english:"Cobbler Admin Interface Detection");
  script_summary(english:"Detects Cobbler Admin Interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A Linux installation server web-based admin interface was detected on
the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A web-based administration interface for Cobbler, a Linux installation
server, was detected on the remote host. "
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:michael_dehaan:cobbler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Cobbler";

port = get_http_port(default:443);

installs = NULL;

url_list = make_list("/cobbler_web", "/cobbler/web");

foreach url (url_list)
{
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if ('<title>Cobbler Web Interface</title>' >< res[2])
  {
    version = 'unknown';
    installs = add_install(
      appname  : "cobbler_web_admin",
      installs : installs,
      port     : port,
      dir      : url,
      ver      : version
    );
  }
}
if (isnull(installs)) audit(AUDIT_NOT_DETECT, appname, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : "",
    display_name : appname
  );
  security_note(port:port, extra:report);
}
else security_note(port);
