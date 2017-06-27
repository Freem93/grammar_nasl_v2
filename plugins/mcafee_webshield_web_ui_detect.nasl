#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58581);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/19 00:13:00 $");

  script_name(english:"McAfee WebShield Web UI Detection");
  script_summary(english:"Looks for WebShield UI");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for a security application was detected on the
remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"WebShield Web UI (included with products such as McAfee Email Gateway
and McAfee Email and Web Security) was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/products/email-gateway.aspx");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a45d4a2");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:webshield");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 10443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:10443);

install = NULL;
dirs = make_list(
  '/admin',   # MEG
  '/scmadmin' # EWS
);

pattern = '<title>(Email Gateway|McAfee Email Gateway|Email and Web Security)[^<0-9.]+([0-9.]+)?<';

foreach dir (dirs)
{
  page = dir + '/';
  res = http_send_recv3(method:'GET', item:page, follow_redirect:3, port:port, exit_on_fail:TRUE);
  match = eregmatch(string:res[2], pattern:pattern);

  if (isnull(match))
  {
    page = dir + '/LocalIndex.html';
    res = http_send_recv3(method:'GET', item:page, port:port, exit_on_fail:TRUE);
    match = eregmatch(string:res[2], pattern:pattern);
  }

  if (isnull(match))
    continue;

  if ('McAfee' >!< match[1])
    display_name = 'McAfee ' + match[1];
  else
    display_name = match[1];

  ver = match[2];
  install = add_install(appname:'mcafee_webshield', dir:dir, ver:ver, port:port);

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:display_name,
      installs:install,
      item:'/',
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
  # never reached
}
audit(AUDIT_WEB_APP_NOT_INST, "McAfee WebShield Web UI", port);
