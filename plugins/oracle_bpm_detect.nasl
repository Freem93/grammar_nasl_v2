#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48338);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 23:56:13 $");

  script_name(english:"Oracle Business Process Management Detection");
  script_summary(english:"Checks for presence of Oracle BPM");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application for business process
management.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running Oracle (formerly BEA) Business
Process Management (BPM) Suite, a set of tools for creating,
executing, and optimizing business processes.");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/us/technologies/bpm/bpm-suite-078529.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8585, 8686);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8585);
ports = add_port_in_list(list:ports, port:8686);

installs = NULL;
foreach port (ports)
{
  res = http_get_cache(item:"/", port:port, exit_on_fail:FALSE);
  if (isnull(res))
  {
    debug_print("The web server on port "+port+" failed to respond.");
    continue;
  }

  # Register the service if necessary.
  if (service_is_unknown(port:port)) register_service(port:port, proto:"www");

  if (
    'BPM Web Applications</title>' >< res &&
    (
      egrep(pattern:'/webconsole.+>Process Administrator', string:res) ||
      egrep(pattern:'/portaladmin.+>WorkSpace Administrator', string:res)
    )
  )
  {
    # Try to get the version number.
    url = '/webconsole/faces/jsp/home.jsp';
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);
    if (isnull(res))
    {
      debug_print("The web server on port "+port+" failed to respond.");
      continue;
    }

    version = '';
    build = '';
    foreach line (split(res[2], keep:FALSE))
    {
      if (ereg(pattern:'^ +Version: [0-9]', string:line))
      {
        version = strstr(line, 'Version: ') - 'Version: ';
      }
      if (ereg(pattern:'^ +Build: #[0-9]', string:line))
      {
        build = strstr(line, 'Build: #') - 'Build: #';
        build = build - '<br>';
      }

      if (version && build)
      {
        version = version + ' Build ' + build;
        break;
      }
    }
    installs = add_install(
      installs:NULL,
      ver:version,
      dir:'/',
      appname:'oracle_bpm',
      port:port
    );

    if (report_verbosity > 0)
    {
      report = get_install_report(
        display_name:'Oracle Business Process Management',
        installs:installs,
        port:port,
        item:'/'
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
if (isnull(installs))
  exit(0, "Oracle BPM was not detected on ports "+join(sep:" & ", ports)+".");
