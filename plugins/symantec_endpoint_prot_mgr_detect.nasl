#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57766);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/18 21:43:21 $");

  script_name(english:"Symantec Endpoint Protection Manager Detection");
  script_summary(english:"Looks for a SEP Manager page.");

  script_set_attribute(attribute:"synopsis", value:
"An endpoint security management interface was detected on the remote
web server.");
  script_set_attribute(attribute:"description", value:
"The management interface for Symantec Endpoint Protection, an endpoint
security solution, was detected on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/endpoint-protection/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Symantec Endpoint Protection Manager";
port = get_http_port(default: 9090);
banner = get_http_banner(port: port);
if (isnull(banner)) audit(AUDIT_NO_BANNER, port);

page = '';
install = '';
if ("Server: SEPM" >< banner)
{
  install = add_install(appname:'sep_mgr', port:port, dir:page);
}
else
{
  page = '/symantec.jsp';
  res = http_send_recv3(method:'GET', item: page, port:port, exit_on_fail:TRUE);
  if (!isnull(res) && '<title>Symantec Endpoint Protection Manager</title>' >< res[2])
  {
    install = add_install(appname:'sep_mgr', port:port, dir:page);
  }
}

if (install)
{
    if (report_verbosity > 0)
    {
      report = get_install_report(
        display_name: appname,
        installs: install,
        port: port
      );
      security_note(port:port, extra:report);
      exit(0);
    }
    else
    {
      security_note(port);
      exit(0);
    }
}

audit(AUDIT_NOT_INST, appname);
