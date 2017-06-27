#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48363);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"IBM Tivoli Management Framework Endpoint Web Detection");
  script_summary(english:"Looks for the TMF Endpoint status page");

  script_set_attribute(attribute:"synopsis", value:"A monitoring application is running on the remote web server.");
  script_set_attribute(
    attribute:"description",
    value:
"Tivoli Endpoint, a component of Tivoli Management Framework, is
running on the remote host.  The remote web application displays the
status of this host's Tivoli Endpoint."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/software/tivoli/products/mgt-framework/");
  script_set_attribute(
    attribute:"solution",
    value:
"Consider restricting access to this port, as the web server displays
information that a remote attacker could use to mount an attack."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_management_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 9495);
  script_dependencies("http11_detect.nasl");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9495, dont_break: TRUE);
res = http_get_cache(item:'/', port:port, exit_on_fail: 1);

if (
  '<TITLE>LCFD Status</TITLE>' >!< res ||
  'Tivoli Management Environment' >!< res ||
  'Endpoint Status' >!< res
) exit(0, 'The server on port ' + port + ' doesn\'t appear to be Tivoli Endpoint.');

info = NULL;
ver = NULL;
items = make_list('Version', 'Windows Version', 'MAC Address', 'Last Restart');

foreach item (items)
{
  pattern = '<TD><B>' + item + ':.*</TD><TD>([^<]+)</TD>';
  match = eregmatch(string:res, pattern:pattern);
  if (match)
  {
    if (item == 'Version') ver = match[1];
    else info += '  ' + item + ' : ' + match[1] + '\n';
  }
}

install = add_install(
  appname:'tivoli_endpoint',
  dir:'',
  ver:ver,
  port:port
);

# register the service if it's still considered unknown (the web server is a
# little wonky and may not have been identified yet)
if (service_is_unknown(port:port))
  register_service(port:port, proto:'www');

replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Tivoli Endpoint',
    installs:install,
    port:port
  );
  if (!isnull(info))
    report += '\nThis page displays information such as :\n\n' + info;

  security_note(port:port, extra:report);
}
else security_note(port);
