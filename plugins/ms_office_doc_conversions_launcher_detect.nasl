#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(51835);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/03/14 21:48:07 $");

  script_name(english:"Microsoft Office Document Conversions Launcher Detection");
  script_summary(english:"Sends an HtmlTrLauncher service request");

  script_set_attribute(attribute:"synopsis", value:
"Microsoft Office Document Conversions Launcher is listening on this
port.");
  script_set_attribute(attribute:"description", value:
"Microsoft Office Document Conversions Launcher is running on this
port.  This service is installed by Microsoft SharePoint Server and
allows for Office Documents to be converted into web documents for use
in SharePoint server.");
  script_set_attribute(attribute:"see_also", value:
"http://msdn.microsoft.com/en-us/library/cc263484(v=office.12).aspx");
  script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?b6da63d6");
  script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it.  This will prevent
documents from being converted." );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl", "ms_office_doc_load_balancer_detect.nasl");
  script_require_ports("Services/unknown", 8082);
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
  port = get_unknown_svc(8082);
  if (!port) exit(0, "There are no unknown services.");
  if (silent_service(port)) exit(0, "The service listening on port "+port+" is silent.");
}
else port = 8082;
if (known_service(port:port)) exit(0, "The service on port "+port+" has already been identified.");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");


hostname = get_host_name();
conversions_launcher_url = get_kb_item("ms_doc_conversions_launcher_url");
if (isnull(conversions_launcher_url))
{ 
  conversions_launcher_url = "http://" + get_host_ip() + ":" + port + "/HtmlTrLauncher";
}

req =
  '<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:clr=\"http://schemas.microsoft.com/soap/encoding/clr/1.0\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n' +
  '<SOAP-ENV:Body>\r\n' +
  '<i2:CHICreateHtml id=\"ref-1\" xmlns:i2=\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLauncher/Microsoft.HtmlTrans.Interface\">\r\n' +
  '<strLauncherUri id=\"ref-4\">' + conversions_launcher_url + '</strLauncherUri>\r\n' +
  '<rgbFile href=\"#ref-5\"/>\r\n' +
  '<bt xsi:type=\"a2:BrowserType\" xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans/Microsoft.HtmlTrans.Interface%2C%20Version%3D12.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D71e9bce111e9429c\">BT_IE4</bt>\r\n' +
  '<strReqFile id=\"ref-6\">nessus.doc</strReqFile>\r\n' +
  '<strTaskName href=\"#ref-6\"/>\r\n' +
  '<timeout>90</timeout>\r\n' +
  '<fReturnFileBits>true</fReturnFileBits>\r\n' +
  '</i2:CHICreateHtml>\r\n' +
  '<SOAP-ENC:Array id=\"ref-5\" xsi:type=\"SOAP-ENC:base64\">OGFjNjVkYzgxNzQ2MzQ4ZjZkNWJhZjdiNTU0MWVkOTU4MjFmNDZjZjYxZDk3OTMwZmYzMDBiZDg3YTQzOGQxYzlmNWE1YTU1NTU4ZWVjM2RjODhkMTYwY2RiMDBjYmM4YzRkMzFmZjBlOTQwMTg0NjBkNDFhNmYwMWU5OGE0OWY0Y2VkY2Q3YTcyMGNkNTFkODUyYWQ5YWQwOGRhNzU1ZDkwZDJkZjhlNmRmN2Q5MmU3MjRkMmVjZDViMzE4YTk4NWRiZDdiZTk4MGVkNjM3NTBmNDQxMDE3M2M0MTA4OTczYTA5NTE3YjA2OWMyZmRmMGM5OWRmZTZjYmVmMWQ0NmRkZWU2NGUx</SOAP-ENC:Array>\r\n' +
  '</SOAP-ENV:Body>\r\n' +
  '</SOAP-ENV:Envelope>\r\n';

# Send a fake job to the service and look for an error.
data = http_send_recv3(
  port:port, 
  host:hostname, 
  method:"POST", 
  item:"/HtmlTrLauncher", 
  data:req, 
  version:11, 
  add_headers:make_array(
    'User-Agent','Mozilla/4.0+(compatible; MSIE 6.0; Windows 6.1.7600.0; MS .NET Remoting; MS .NET CLR 4.0.30319.1 )',
    'Content-Type','text/xml; charset=\"utf-8\"',
    'SOAPAction','\"http://schemas.microsoft.com/clr/nsassem/Microsoft.HtmlTrans.IHtmlTrLauncher/Microsoft.HtmlTrans.Interface#CHICreateHtml\"',
    'Expect', '100-continue'
  ), 
  exit_on_fail:TRUE
);

if (
  "HTTP/1.1 200 OK" >< data[0] &&
  !isnull(data[2]) &&
  (
    "<m_ce>CE_OTHER</m_ce>" >< data[2] || 
    "<m_ce>CE_OTHER_BLOCKLIST</m_ce>" >< data[2]
  )
) 
{
  security_note(port);
  register_service(port:port, proto:"ms_doc_conversions_launcher");
  exit(0);
}
else exit(0, "The service listening on port "+port+" did not send an expected response to an HtmlTrLauncher service request.");
