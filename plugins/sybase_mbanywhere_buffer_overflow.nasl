#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54618);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  
  script_bugtraq_id(47775);
  script_osvdb_id(72256);

  script_name(english:"Sybase M-Business Anywhere (AvantGo) gsoap Module password Tag Handling Overflow");
  script_summary(english:"Sends a SOAP request with an overly long password XML tag");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SOAP server is vulnerable to a buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sybase M-Business Anywhere (AvantGo) software installed on the
remote host includes a SOAP server that fails to validate an XML end tag in
a SOAP request, resulting in a buffer overflow. 

An unauthenticated, remote attacker can exploit this to execute
arbitrary code. 
       
This plugin checks the heap overflow condition in the SOAP server by
submitting a request with a long XML end tag."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-154/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2011/May/71"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.sybase.com/detail?id=1093029"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the appropriate patch from Sybase."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-155/");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-156/");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
  
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencie("sybase_mbanywhere_soap_server_detect.nasl");
  script_require_keys("Services/AvantGo-soap-server");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www",8093,8094);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

##
# create a SOAP request
# 
# @param tag        - XML tag for the 'password'
# @param username   - username to use to login
# @param password   - password to use to login
# 
# @return a SOAP request
#
##
function mk_soap_req(tag, username, password)
{
  local_var req;
  
  if(isnull(password)) password = rand_str(length:16);
      
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
    '<userName xsi:type="xsd:string">' + username + '</userName>' +
    '<' + tag +'>' + ' xsi:type="xsd:string">' + password + '</' + tag + '>' +
    '</q1:loginUser>' +
    '</soap:Body>'    +
    '</soap:Envelope>';
  
  return req;
}

port = get_kb_item_or_exit("Services/AvantGo-soap-server");

username = rand_str(length:16);

pat = "AvantgoWebAPI.*<faultstring>agapi__loginUser: invalid login</faultstring><detail>" + username + "</detail>";

# send a request with an invalid tag (tag length exceeds 256 bytes)
# vulnerable server doesn't check the end tag length, and sends back a response
req = mk_soap_req(tag:crap(data:"T", length:257), username:username);
res = http_send_recv3(method:"POST", port:port, item:"/agsoap", data:req, content_type:"text/xml");
if (!isnull(res))
{
  if (res[2] =~ pat)
  {
    security_hole(port);
    exit(0);
  }
  else exit(1, 'The web server on port ' + port + ' returned an unexpected response:\n' + res[2]);
}

# Patched soap server doesn't respond if an end tag exceeds 256 bytes
# test again
# same request, only difference is the tag len is 1 byte less, which is a valid tag length
req =  mk_soap_req(tag:crap(data:"T", length:256), username:username);
res = http_send_recv3(method:"POST", port:port, item:"/agsoap", data:req, content_type:"text/xml");
if (!isnull(res))
{
  if (res[2] =~ pat)
    exit(0, 'The web server on port ' +port+ ' is patched.');
  else exit(1, 'The web server on port ' + port + ' returned an unexpected response:\n' + res[2]);
}
else exit(1, 'The web server on port '+port+' did not respond.');
