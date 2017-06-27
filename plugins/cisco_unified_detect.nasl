#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70088);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/17 21:07:40 $");

  script_name(english:"Cisco CUCM / CUPS Detection");
  script_summary(english:"Detects the version of a CUCM / CUPS host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running Cisco Unified Communications Manager (CUCM)
or Cisco Unified Presence Server (CUPS).");
  script_set_attribute(attribute:"description", value:
"Cisco Unified Communications Manager (CUCM) or Cisco Unified Presence
Server (CUPS) is running on the remote host. This plugin extracts its
version number by using the provided cleartext HTTP credentials to
issue an encrypted GetServerInfo or GetProductInformationList call via
HTTPS to Real-Time Information Services (RisPort, RISService, or
RISService70) or the ControlCenterServices SOAP API.");
  # http://www.cisco.com/c/en/us/products/unified-communications/unified-communications-manager-callmanager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b42c100e");
  # http://www.cisco.com/c/en/us/products/unified-communications/unified-presence/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc61a457");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_require_keys("http/password", "http/login");
  script_dependencies("find_service1.nasl");
  script_require_ports(443, 8443);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

username = get_kb_item_or_exit("http/login");
password = get_kb_item_or_exit("http/password");

# < 10.x uses port 8443
# 10.x uses port 443
port = get_http_port(default:8443);

# Send POST request to the XML SOAP API
function post_soap(path, data)
{
  local_var i, response, raw_response;

  raw_response =  http_send_recv3(
                    method:"POST",
                    port:port,
                    item:path,
                    add_headers:make_array(
                      "SOAPAction", '\"\"',
                      "Authorization", "Basic " + base64(str:username+":"+password)
                    ),
                    content_type    : "application/x-www-form-urlencoded",
                    follow_redirect : 1,
                    data:data
                  );
  # If a part of the reply was null, replace with an empty string so
  # we can # safely match and compare. For our purposes, null and the
  # empty string are equivalent.
  for (i = 0; i < 3; i++)
  {
    if (isnull(raw_response[i]))
      raw_response[i] = "";
  }

  response = make_array();
  response["status"]  = raw_response[0];
  response["headers"] = raw_response[1];
  response["body"]    = raw_response[2];

  return response;
}

api_list = make_nested_list(
  # ~8.6
  make_array(
    "path", "/realtimeservice2/services/RISService",

    "soap_request",
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
         xmlns:soap="http://schemas.cisco.com/ast/soap">
       <soapenv:Header/>
       <soapenv:Body>
         <soap:getServerInfo>
           <soap:Hosts>
             <soap:Name>localhost</soap>
           </soap:Hosts>
         </soap:getServerInfo>
       </soapenv:Body>
     </soapenv:Envelope>',

    "regex", "<ns1:call-manager-version>([0-9.-]+)</ns1:call-manager-version>"
  ),

  # 9.x / 10.x (deprecated -- but still works)
  make_array(
    "path", "/realtimeservice/services/RisPort",

    "soap_request",
    '<soapenv:Envelope
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema"
          xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
          xmlns:soap="http://schemas.cisco.com/ast/soap/">
      <soapenv:Header />
      <soapenv:Body>
        <soap:GetServerInfo soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
          <Hosts xsi:type="soap:ArrayOfHosts">
	    <item xsi:type="xsd:string">localhost</item>
          </Hosts>
        </soap:GetServerInfo>
      </soapenv:Body>
    </soapenv:Envelope>',

    "regex", '<call-manager-version xsi:type="xsd:string">([0-9.-]+)\\.?\\w*</call-manager-version>'
  ),

  # 10.x
  make_array(
    "path", "/controlcenterservice/services/ControlCenterServicesPort",

    "soap_request",
    '<!-- getProductInformationList Request format  -->
    <soapenv:Envelope
      xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
      xmlns:soap="http://schemas.cisco.com/ast/soap">
    <soapenv:Header/>
      <soapenv:Body>
        <soap:GetProductInformationList>
          <soap:ServiceInfo>?</soap:ServiceInfo>
        </soap:GetProductInformationList>
      </soapenv:Body>
    </soapenv:Envelope>',
    "regex", '<ActiveServerVersion xsi:type="xsd:string">([0-9.-]+)\\.?\\w*</ActiveServerVersion>'

  )
);

api_num = 0; # API number we were able to connect with
pat = NULL;

for (i=0; i < max_index(api_list); i++)
{
  response = post_soap(path:api_list[i]["path"], data:api_list[i]["soap_request"]);
  # We can exit immediately because the APIs will use the same password
  if ("HTTP/1.1 401 Unauthorized" >< response["status"])
    exit(0, "401 Unauthorized received");

  if ("HTTP/1.1 200" >!< response["status"])
    continue;

  api_num = i;
  pat = api_list[i]["regex"];
  break;
}

if (!api_num)
  audit(AUDIT_WEB_APP_NOT_INST, "The Cisco Serviceability XML API", port);

# Check that the response is SOAP
if (!ereg(string:response["body"], pattern:'^<\\?xml version=.1\\.0. encoding=.UTF-8.\\?><soapenv:Envelope'))
  audit(AUDIT_RESP_BAD, port, "HTTP POST with SOAP payload (non-SOAP response)");

matches = eregmatch(string:response["body"], pattern:pat);
if (isnull(matches) || isnull(matches[0]) || isnull(matches[1]))
  audit(AUDIT_SERVICE_VER_FAIL, "Cisco Serviceability XML API", port);

version_display = matches[1];

service = NULL;

# It's possible that both CUPS and CUCM exist on the same server
if (' ucm-cucmws-' >< response["body"] ||
    ' ucm-cucm-' >< response["body"] ||
    'Cisco Unified Communications Manager' >< response["body"] ||
    'Cisco Unified CallManager' >< response["body"]
)
{
  version = str_replace(string:version_display, find:"-", replace:".");
  set_kb_item(name:"cisco_cucm/version", value:version);
  set_kb_item(name:"cisco_cucm/version_display", value:version_display);
  service = "CUCM";
}

if (' cup-selinux-' >< response["body"])
{
  set_kb_item(name:"cisco_cups/system_version", value:version_display);
  if (isnull(service))
    service = "CUPS";
  else
    service += " and CUPS";
}

if (isnull(service))
  audit(AUDIT_SERVICE_VER_FAIL, "Cisco CUCM/CUPS", port);

report = NULL;
if (report_verbosity > 0)
{
  report = '\nNessus was able to obtain the version number of ' + service + ' by logging in to the Cisco Serviceability XML API.' +
           '\nThe version is : ' + version_display + '\n';
}
security_note(port:port, extra:report);
