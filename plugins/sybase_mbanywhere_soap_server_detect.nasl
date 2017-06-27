#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54616);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/05/24 02:04:26 $");

  script_name(english:"Sybase M-Business Anywhere (AvantGo) SOAP Server Detection");
  script_summary(english:"Checks for response from the M-Business SOAP server");

  script_set_attribute(
    attribute:"synopsis",
    value:"A administrative service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service is a Sybase M-Business Anywhere (formerly AvantGo)
SOAP Server, which provides a web-based programming interface to
server administration tasks in M-Business, such as configuration,
group, user, and web channel management."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.sybase.com/products/allproductsa-z/m-businessanywhere"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8093, 8094);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8093);

# check for AvantGo web server
# the soap server in M-Business Anywhere uses the 'AvantGo' server string 
srv_hdr = http_server_header(port:port);
if (isnull(srv_hdr)) 
  exit(0, "The banner from the web server on port "+port+" does not have a Server response header.");
if ("AvantGo" >!< srv_hdr)
  exit(0, "The web server on port " +port+ " does not appear to be Sybase M-Business Anywhere (AvantGo) SOAP Server.");
  
username = rand_str(length:16);
password = rand_str(length:16);
  
req = 
    '<?xml version="1.0" encoding="utf-8"?>' +
    '<soap:Envelope ' + 
    'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' +  
    'xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" ' +
    'xmlns:tns="http://localhost:8094/avantgoapi.wsdl" '+ 
    'xmlns:types="http://localhost:8094/avantgoapi.wsdl/encodedTypes" ' + 
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +  
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
    '<soap:Body soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    '<q1:loginUser xmlns:q1="urn:AvantgoWebAPI">' +
    '<userName xsi:type="xsd:string">'+ username +'</userName>' +
    '<b64password xsi:type="xsd:string">' + password +'</b64password>' +
    '</q1:loginUser>' +
    '</soap:Body>'    +
    '</soap:Envelope>';

res = http_send_recv3(method:"POST", port:port, item:"/agsoap",
                      data:req, content_type:"text/xml", exit_on_fail:TRUE);


if (res[2] && res[2] =~ "AvantgoWebAPI.*<faultstring>agapi__loginUser: invalid login</faultstring><detail>" + username + "</detail>")
{
  register_service(port:port, proto:"AvantGo-soap-server");
  security_note(port);
}
else exit(1, 'The web server on port ' + port + ' returned an unexpected response:\n' + res[2]);

  
  
