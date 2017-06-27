#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22477);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"SOAP Server Detection");
  script_summary(english:"Detects a SOAP Server");

  script_set_attribute(attribute:"synopsis", value:"There is a SOAP server listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a SOAP server. SOAP, originally an acronym
for 'Simple Object Access Protocol', is an XML-based distributed
messaging protocol typically implemented over HTTP.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SOAP");
  script_set_attribute(attribute:"see_also", value:"http://www.w3.org/TR/soap12-part0/" );
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (get_kb_item("global_settings/disable_service_discovery"))
  exit(0, "Service discovery is disabled in the scan policy.");
if (!thorough_tests)
 exit(0, "This plugin only runs if the 'Perform thorough tests' setting is enabled.");
port = get_unknown_svc(0);           # nb: no default
if (!port) exit(0, "No unknown services.");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is closed.");


# Send a simple SOAP method request.
urn = "example-com:nessus";
method = "getPluginResults";

postdata = strcat(
  "<?xml version='1.0' ?>", '\n',
  '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
  "<soap:Body>", '\n',
  '   <i:', method, ' xmlns:i="', urn, '">\n',
  '     <pluginName>', SCRIPT_NAME, '</pluginName>\n',
  '   </i:', method, '>\n',
  ' </soap:Body>\n',
  '</soap:Envelope>'
);
w = http_send_recv3(method:"POST", port: port, item: "/",
  add_headers: make_array("SOAPMethodName", "urn:"+urn+"#"+method),
  content_type: "text/xml",
  exit_on_fail: 1,
  data: postdata);
res = w[2];

# It's a SOAP server if we see an error involving our URN.
if (
  string("java.lang.ClassNotFoundException: Failed to locate SOAP processor: ", urn) >< res ||
  string("<faultstring>Method 'i:", method, "' not implemented") >< res ||
  "<faultcode>SOAP-ENV:Server</faultcode>" >< res ||
  "<faultcode>soap:Client</faultcode>" >< res
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"soap_http");

  security_note(port);
}
else
  exit(0, "SOAP was not detected on port "+port+".");
