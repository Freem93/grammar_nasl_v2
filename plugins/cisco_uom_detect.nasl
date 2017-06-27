#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56484);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"Cisco Unified Operations Manager Detection");
  script_summary(english:"Looks for the UOM login page");

  script_set_attribute(attribute:"synopsis", value:"A monitoring application is hosted on the remote web server.");
  script_set_attribute(
    attribute:"description",
    value:
"Cisco Unified Operations Manager, part of the Cisco Unified
Communications Management Suite, was detected on the remote web
server.  Unified Operations Manager is used to perform real-time
monitoring."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps6535/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_operations_manager");
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
dir = '';
page = '/CSCOnm/servlet/login/login.jsp';
url = dir + page;

res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);
if ('Login</title>' >!< res[2] || res[2] !~ 'productName=["\'](Cisco )?Unified Operations Manager["\']')
  exit(0, 'Cisco UOM doesn\'t appear to be running on port ' + port + '.');

match = eregmatch(string:res[2], pattern:'productVersion=["\'](Version )?([0-9.]+)["\']');
if (isnull(match))
  ver = NULL;
else
  ver = match[2];

install = add_install(
  appname:'cisco_uom',
  dir:dir,
  port:port,
  ver:ver
);

# accessing the document root results in a 403, we'll save the login page so
# any other CUOM plugins can use it when they need to report the CUOM URL
set_kb_item(name:'/tmp/cuom/' + port + '/loginpage', value:page);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Cisco Unified Operations Manager',
    installs:install,
    port:port,
    item:page
  );
  security_note(port:port, extra:report);
}
else security_note(port);

