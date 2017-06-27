#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35708);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2016/10/13 15:15:41 $");

 script_name(english: "UPnP Internet Gateway Device (IGD) External IP Address Reachable");
 script_summary(english: "Call GetExternalIPAddress on UPnP IGD router.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to read the external IP address of the remote router.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device is a NAT router which
supports the Internet Gateway Device (IGD) Standardized Device Control
Protocol. Nessus was able to retrieve the external IP address of the
device.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
 script_set_attribute(attribute:"solution", value:
"Disable IGD or restrict access to trusted networks.");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');

port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');
services = get_kb_list('upnp/'+port+'/service');

vuln = FALSE;
foreach(service in services)
{
  serviceType = get_kb_item_or_exit('upnp/'+port+'/service/'+service+'/serviceType');
  if (isnull(serviceType) ||
      ("WANIPConnection" >!< serviceType && "WANPPPConnection" >!< serviceType)) continue;

  ctrlUrl = get_kb_item('upnp/'+port+'/service/'+service+'/controlURL');
  if (isnull(ctrlUrl)) continue;

  payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<s:Body>' +
    '<u:GetExternalIPAddress xmlns:u="' + service + '">' +
    '</u:GetExternalIPAddress>' +
    '</s:Body>' +
    '</s:Envelope>';

  soapAction = ('"' + service + '#' + 'GetExternalIPAddress' + '"');
  resp = http_send_recv3(method: 'POST',
                         item: ctrlUrl,
                         port: port,
                         content_type: 'text/xml;charset="utf-8"',
                         add_headers:make_array('SOAPAction', soapAction),
                         data: payload,
                         host: get_host_ip(),
                         exit_on_fail: FALSE);

  if (isnull(resp) || '200 OK' >!< resp[0] || len(resp[2]) == 0) continue;

  r = eregmatch(string: resp[2], pattern: "<NewExternalIPAddress>([0-9.]+)</NewExternalIPAddress>");
  if (isnull(r)) continue;

  report = '';
  full_url = 'http://' + get_host_ip() + ':' + port + url['url'];
  if (r[1] == "0.0.0.0")
  {
    report = '\nThe remote device erroneously responded to the GetExternalIPAddress\n' +
             'request to ' + full_url + ' with the following address :\n\n' +
             r[1] + '\n';
  }
  else
  {
    set_kb_item(name: "upnp/external_ip_addr", value: r[1]);
    report = '\nThe remote device responded to the GetExternalIPAddress request to\n' +
             full_url + ' with following address :\n\n' +
             r[1]+ '\n';
  }

  vuln = TRUE;
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}

if (vuln == FALSE) audit(AUDIT_HOST_NOT, 'affected');
