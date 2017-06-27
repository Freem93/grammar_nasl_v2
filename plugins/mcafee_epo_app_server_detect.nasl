#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66318);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/05 00:07:05 $");

  script_name(english:"McAfee ePolicy Orchestrator Application Server Detection");
  script_summary(english:"Looks for the ePO App Server login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web management interface for a security management application was
detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"ePolicy Orchestrator (ePO) Application Server, a web interface for ePO,
was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/products/epolicy-orchestrator.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);
dir = '';
page = '/core/orionSplashScreen.do';
res = http_send_recv3(method:'GET', item:dir + page, port:port, exit_on_fail:TRUE);

match = eregmatch(string:res[2], pattern:"ePolicy Orchestrator ([\d.]+)");
if (isnull(match)) audit(AUDIT_WEB_APP_NOT_INST, 'ePO Application Server', port);

ver = match[1];
install = add_install(appname:'epo_app_server', port:port, dir:dir, ver:ver);

if (report_verbosity > 0)
{
  report = get_install_report(
    installs:install,
    port:port,
    display_name:'McAfee ePolicy Orchestrator Application Server',
    item:page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
