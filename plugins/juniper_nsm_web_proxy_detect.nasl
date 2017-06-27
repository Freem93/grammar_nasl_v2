#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69875);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/13 16:48:17 $");

  script_name(english:"Juniper NSM Web Proxy Detection");
  script_summary(english:"Detects NSM Web Proxy");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a web proxy."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running the Juniper NSM Web Proxy, which is used for
hosting NSM GUI client software and web-based APIs."
  );
  # http://www.juniper.net/us/en/products-services/software/network-management-software/nsm/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11d258f7");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8443);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);

res = http_send_recv3(method:'GET', item:'/', port:port, exit_on_fail:TRUE);

if (
  '<title>Network and Security Manager - Download UI Client</title>' >!< res[2] ||
  'Windows UI Client' >!< res[2] || 'Linux UI Client' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, 'Juniper NSM Web Proxy', port);

install = add_install(
  appname:'juniper_nsm_web_proxy',
  dir:'',
  port:port,
  ver:NULL
);

soap_wsdl = '/axis2/services/SystemService?wsdl';

# check to see if SOAP interface is available
res = http_send_recv3(method:'GET', item:soap_wsdl, port:port, exit_on_fail:TRUE);
if (
  'http://juniper.net/webproxy/systemservice' >< res[2] &&
  '"LoginStatus"' >< res[2] && '"GetSystemInfoRequest"' >< res[2]
) set_kb_item(name:'www/' + port + '/juniper_nsm_web_proxy/soap_available', value:soap_wsdl);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Juniper NSM Web Proxy',
    installs:install,
    port:port,
    item:'/'
  );
  security_note(port:port, extra:report);
}
else security_note(port);

