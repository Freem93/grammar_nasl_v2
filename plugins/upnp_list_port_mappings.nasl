#TRUSTED 7e365aaeca2e596e6fd69220137ab619beab78dd4612321de4dc083453325874797b205d572623ede10ee1eda7fb26e6fa3a0e4c60192ee0d83328b781cc54ae7125a2ad9ef52e7cab22eaf53eb617bec83850544c9fca2767b3aca151bf6f7b517c73286eec805bce9178d8255858efeadb6dda2688ec7702eac8990b5d5955f2f4af5a85ca9e5ef91a1832cf8b4bce6417f8b1ae2b3b9e3a308851981ccb73a54cece77d85c9251186071074ee9667181c739eab307ff43142ffc0305db35e37fe5abbabe300f9ddd06bf6883f3a2086e496f38dab576a3d228a98bd65ca2ac3aad9d2f387d3c0fc2b8dd3dc0e9a3daf93d1c66eb0192476888e2245328ba1f2d3bd85604b7ff15dcc56e91dea97a0ac86991cf34a7730443e949702af06f821ec5e5b4dc92bef7765a65239f111d5a7bf6a9f1b1adc9651c042deab49419149dea14d074ae483640e1dda20a6721a61ab9c5d1091009d499b7ed488365d9b42561442675588d94253a576c4be4e45dc01610c46e2c0ecdfbe640bfba953ca2efd2533ffbc73ed01b37b34be312e39d37ae5102ba8fde598e606a4fcb69a164ddbfd86f3bad59ea622aed79357e230d20da0cbfcd6a5af6d6b01093a8926ad208cc5ec570027c6364ebdc97b325ecb44c6f6dea31cc34eea54587d65b833891bbfc1cad02f4bdb65c2d5add48b079ad58005cb2f49622e8742bf2342ddef8c

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(94048);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/24");

 script_xref(name:"CERT", value:"361684");

 script_name(english: "UPnP Internet Gateway Device (IGD) Port Mapping Listing");
 script_summary(english: "Lists the current IGD port mappings.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to list the port mappings created via UPnP IGD on the
remote device.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device is a NAT router that
supports the Internet Gateway Device (IGD) Standardized Device Control
Protocol. Nessus was able to list 'port mappings' that redirect ports
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
 script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('xml_func.inc');
include('audit.inc');
include('http.inc');

port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');
services = get_kb_list('upnp/'+port+'/service');

##
# Parses the 'GetGenericPortMappingEntryResponse' XML and
# extracts the relevant values to display to the user.
#
# @param xml the XML string we received via HTTP
# @return a string representation of the port mapping
##
function parse_mapping(xml)
{
  local_var rootxml = xmlparse(xml);
  if (isnull(rootxml)) return NULL;

  local_var body = xml_get_child(table:rootxml, name:'s:Body');
  if (isnull(body)) return NULL;

  local_var mapping = xml_get_child(table:body, name:'u:GetGenericPortMappingEntryResponse');
  if (isnull(mapping)) return NULL;

  local_var remoteHost = xml_get_child(table:mapping, name:'NewRemoteHost');
  if (isnull(remoteHost)) return NULL;
  if (isnull(remoteHost['value'])) remoteHost['value'] = '*';

  local_var extPort = xml_get_child(table:mapping, name:'NewExternalPort');
  if (isnull(extPort) || isnull(extPort['value'])) return NULL;

  local_var protocol = xml_get_child(table:mapping, name:'NewProtocol');
  if (isnull(protocol) || isnull(protocol['value'])) return NULL;

  local_var intPort = xml_get_child(table:mapping, name:'NewInternalPort');
  if (isnull(intPort) || isnull(intPort['value'])) return NULL;

  local_var intHost = xml_get_child(table:mapping, name:'NewInternalClient');
  if (isnull(intHost) || isnull(intHost['value'])) return NULL;

  local_var map_string = '\t[' + protocol['value'] + '] ' + remoteHost['value'] +
    ':' + extPort['value'] + ' -> ' + intHost['value'] + ':' + intPort['value'] + '\n';

  return map_string;
}

report = '';
vuln = FALSE;
foreach(service in services)
{
  serviceType = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/serviceType'));
  if (isnull(serviceType) || len(serviceType) != 1) continue;
  serviceType = serviceType[0];

  if ("WANIPConnection" >!< serviceType && "WANPPPConnection" >!< serviceType) continue;

  ctrlUrl = list_uniq(get_kb_list('upnp/'+port+'/service/'+service+'/controlURL'));
  if (isnull(ctrlUrl) || len(ctrlUrl) != 1) continue;
  ctrlUrl = ctrlUrl[0];

  all_mappings = '';
  for (i = 0; i < 1024; i++)
  {
    payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
      '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
      '<s:Body>' +
      '<u:GetGenericPortMappingEntry xmlns:u="' + service + '">' +
      '<NewPortMappingIndex>' + i + '</NewPortMappingIndex>' +
      '</u:GetGenericPortMappingEntry>' +
      '</s:Body>' +
      '</s:Envelope>';

    soapAction = ('"' + service + '#' + 'GetGenericPortMappingEntry' + '"');
    resp = http_send_recv3(method: 'POST',
                           item: ctrlUrl,
                           port: port,
                           content_type: 'text/xml;charset="utf-8"',
                           add_headers:make_array('SOAPAction', soapAction),
                           data: payload,
                           host:get_host_ip(),
                           exit_on_fail: FALSE);

    if (isnull(resp) || '200 OK' >!< resp[0]) break;

    port_mapping = parse_mapping(xml:resp[2]);
    if (isnull(port_mapping)) break;
    all_mappings += port_mapping;
  }

  if (len(all_mappings) > 0)
  {
    vuln = TRUE;
    full_url = 'http://' + get_host_ip() + ':' + port + ctrlUrl;
    report += '\nThe remote device at ' + full_url + ' contains the following port mappings :\n';
    report += all_mappings;
  }
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
else security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
