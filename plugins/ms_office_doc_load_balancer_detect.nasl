#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(51834);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/01/19 19:53:34 $");

  script_name(english:"Microsoft Office Document Conversions Load Balancer Detection");
  script_summary(english:"Sends an HtmlTrLoadBalancer service request");

  script_set_attribute(attribute:"synopsis", value:
"Microsoft Office Document Conversions Load Balancer is listening on
this port.");
  script_set_attribute(attribute:"description", value:
"Microsoft Office Document Conversions Load Balancer is running on
this port.  This service aides in the discovery of the Microsoft
Office Document Conversions Launcher service and controls how jobs are
routed to Conversions Launcher services.");
  script_set_attribute(attribute:"see_also", value:
"http://msdn.microsoft.com/en-us/library/cc263484(v=office.12).aspx");
  script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?b6da63d6");
  script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it.  This will prevent the
discovery of the Document Conversion Launcher service.  Documents will
still be able to be converted by directly talking to the Document
Conversion Launcher service." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 8093);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (
  thorough_tests && 
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(8093);
  if (!port) exit(0, "There are no unknown services.");
  if (silent_service(port)) exit(0, "The service listening on port "+port+" is silent.");
}
else port = 8093;
if (known_service(port:port)) exit(0, "The service on port "+port+" has already been identified.");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");


# Test the port first for a 500 error.
hostname = get_host_name();
req =
 '<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n' +
 '<SOAP-ENV:Body>\r\n<i2:StrGetLauncher id=\"ref-1\" xmlns:i2=\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLoadBalancer/Microsoft.HtmlTrans.Interface\">\r\n' +
 '<strTaskName id=\"ref-3\">nessus.doc</strTaskName>\r\n' +
 '</i2:StrGetLauncher>\r\n' +
 '</SOAP-ENV:Body>\r\n' +
 '</SOAP-ENV:Envelope>\r\n';

data = http_send_recv3(
  port:port, 
  host:hostname, 
  method:"GET", 
  item:"/HtmlTrLoadBalancer", 
  data:req, 
  version:11, 
  add_headers:make_array(
    'User-Agent','Mozilla/4.0+(compatible; MSIE 6.0; Windows 6.1.7600.0; MS .NET Remoting; MS .NET CLR 4.0.30319.1 )',
    'Content-Type','text/xml; charset=\"utf-8\"',
    'SOAPAction','\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLoadBalancer/Microsoft.HtmlTrans.Interface#StrGetLauncher\"',
    'Expect', '100-continue'
  ), 
  exit_on_fail:TRUE
);
if ("HTTP/1.1 500 Server" >!< data[0])
{
  exit(1, "The service listening on port "+port+" did not return an HTTP 500 response as expected.");
}


# Start a job and retrieve the url of the converter.
data = http_send_recv3(
  port:port, 
  host:hostname, 
  method:"POST", 
  item:"/HtmlTrLoadBalancer", 
  data:req, 
  version:11, 
  add_headers:make_array(
    'User-Agent','Mozilla/4.0+(compatible; MSIE 6.0; Windows 6.1.7600.0; MS .NET Remoting; MS .NET CLR 4.0.30319.1 )',
    'Content-Type','text/xml; charset=\"utf-8\"',
    'SOAPAction','\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLoadBalancer/Microsoft.HtmlTrans.Interface#StrGetLauncher\"',
    'Expect', '100-continue'
  ), 
  exit_on_fail:TRUE
);
if (
  "HTTP/1.1 200 OK" >!< data[0] || 
  isnull(data[2]) || 
  'i2:StrGetLauncherResponse' >!< data[2]
) exit(0, "The service listening on port "+port+" did not respond as expected to the first HtmlTrLoadBalancer service request.");

conversions_launcher_url = eregmatch(
  pattern:'<i2:StrGetLauncherResponse id=".*" xmlns:i2=".*">\r\n<return id=".*">(.*)</return>\r\n</i2:StrGetLauncherResponse>', 
  string:data[2]
);

if (
  isnull(conversions_launcher_url) ||
  (
    "http://"  >!< conversions_launcher_url[1] &&
    "https://" >!< conversions_launcher_url[1]
  )
) exit(0, "Failed to get the Microsoft Office Document Conversions Launcher URL from the service listening on port "+port+".");


# Report the service.
set_kb_item(name:'ms_doc_conversions_launcher_url', value:conversions_launcher_url[1]);
register_service(port:port, proto:"ms_doc_conversions_load_balancer");

if (report_verbosity > 0)
{
  report = '\n' + 'Using an HtmlTrLoadBalancer service request, Nessus was able to' +
           '\n' + 'retrieve the following URL for the Microsoft Office Document' +
           '\n' + 'Conversions Launcher : ' +
           '\n' +
           '\n' + '  ' + conversions_launcher_url[1] + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);


# Clean up the LoadBalancers queue for the conversions.
req =
 '<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n' +
 '<SOAP-ENV:Body>\r\n' +
 '<i2:LauncherTaskCompleted id=\"ref-1\" xmlns:i2=\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLoadBalancer/Microsoft.HtmlTrans.Interface\">\r\n' +
 '<strLauncherUri id=\"ref-3\">http://SHAREPOINT2007:8082/HtmlTrLauncher</strLauncherUri>\r\n' +
 '<strTaskName id=\"ref-4\">nessus.doc</strTaskName>\r\n' +
 '</i2:LauncherTaskCompleted>\r\n' +
 '</SOAP-ENV:Body>\r\n' +
 '</SOAP-ENV:Envelope>\r\n\r\n';

http_send_recv3(
  port:port, 
  host:hostname, 
  method:"POST", 
  item:"/HtmlTrLoadBalancer", 
  data:req, 
  version:11, 
  add_headers:make_array(
    'User-Agent','Mozilla/4.0+(compatible; MSIE 6.0; Windows 6.1.7600.0; MS .NET Remoting; MS .NET CLR 4.0.30319.1 )',
    'Content-Type','text/xml; charset=\"utf-8\"',
    'SOAPAction','\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLoadBalancer/Microsoft.HtmlTrans.Interface#LauncherTaskCompleted\"',
    'Expect', '100-continue'
  )
);
