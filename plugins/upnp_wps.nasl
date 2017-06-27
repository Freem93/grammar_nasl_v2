#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(94049);
 script_version("$Revision: 1.1 $");
 script_cvs_date("$Date: 2016/10/13 15:15:41 $");

 script_name(english: "UPnP WFA Device Detection");
 script_summary(english: "Retrieves the M1 message from the UPnP Server.");

 script_set_attribute(attribute:"synopsis", value:
"The remote UPnP server supports the WFA Device specification.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device implements a UPnP WFA
Device profile. This interface allows a user to configure WiFi
settings over UPnP. The specifications requires a WPS-like
authentication scheme.");
 # https:#www.wi-fi.org/download.php?file=/sites/default/files/private/WFA_Device_1_0_Template_1_01.pdf
 script_set_attribute(attribute:"see_also", value:"http:#www.nessus.org/u?fe9f26f6");
 script_set_attribute(attribute:"solution", value:
"Disable WPS if possible.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");

 script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

##
# Takes a mac in raw byte format and returns the mac in a printable
# form. The way this is done seems hacky, but I don't know a
# better NASL way to do it.
#
# @param mac the mac address in raw binary
# @return the mac address in human readable
##
function format_mac(mac)
{
  local_var retVal = '';

  if (len(mac) != 6) return retVal;

  retVal = substr(hex(getbyte(blob:mac, pos:0)), 2);
  retVal += ':';
  retVal += substr(hex(getbyte(blob:mac, pos:1)), 2);
  retVal += ':';
  retVal += substr(hex(getbyte(blob:mac, pos:2)), 2);
  retVal += ':';
  retVal += substr(hex(getbyte(blob:mac, pos:3)), 2);
  retVal += ':';
  retVal += substr(hex(getbyte(blob:mac, pos:4)), 2);
  retVal += ':';
  retVal += substr(hex(getbyte(blob:mac, pos:5)), 2);
  return retVal;
}

report = '';
vuln = FALSE;
foreach(service in services)
{
  serviceType = get_kb_item_or_exit('upnp/'+port+'/service/'+service+'/serviceType');
  if (isnull(serviceType) || ("WFAWLANConfig" >!< serviceType)) continue;

  ctrlUrl = get_kb_item('upnp/'+port+'/service/'+service+'/controlURL');
  if (isnull(ctrlUrl)) continue;

  payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
    '<s:Envelope s:encodingStyle="http:#schemas.xmlsoap.org/soap/encoding/" xmlns:s="http:#schemas.xmlsoap.org/soap/envelope/">' +
    '<s:Body>' +
    '<u:GetDeviceInfo xmlns:u="' + serviceType + '">' +
    '</u:GetDeviceInfo>' +
    '</s:Body>' +
    '</s:Envelope>';

  soapAction = ('"' + serviceType + '#' + 'GetDeviceInfo' + '"');
  resp = http_send_recv3(method: 'POST',
                         item: ctrlUrl,
                         port: port,
                         content_type: 'text/xml;charset="utf-8"',
                         add_headers: make_array('Soapaction', soapAction),
                         data: payload,
                         host: get_host_ip(),
                         exit_on_fail: FALSE);

  if (isnull(resp) || '200 OK' >!< resp[0]) continue;

  deviceInfo = eregmatch(pattern:"<NewDeviceInfo>(.+)</NewDeviceInfo>", string:resp[2]);
  if (isnull(deviceInfo)) continue;

  decoded = base64_decode(str: deviceInfo[1]);
  if (isnull(decoded)) continue;

  index = 0;
  collect = '';
  decoded_len = len(decoded);
  while ((index + 4) < decoded_len)
  {
    # handle the TLV
    type = getword(blob:decoded, pos:index);
    index += 2;
    length = getword(blob:decoded, pos:index);
    index += 2;
    if ((index + length) > decoded_len) break;
    value = substr(decoded, index, index + length - 1);

    if (type == 0x1023) collect += '\tModel Name: ' + value + '\n';
    else if (type == 0x1021) collect += '\tManufacturer: ' + value + '\n';
    else if (type == 0x1011) collect += '\tDevice Name: ' + value + '\n';
    else if (type == 0x1020) collect += '\tMAC Address: ' + format_mac(mac:value) + '\n';
    else if (type == 0x1032) collect += '\tPublic Key: ' + hexstr(value) + '\n';
    else if (type == 0x101a) collect += '\tNonce: ' + hexstr(value) + '\n';

    # step to the next TLV
    index += length;
  }

  if(len(collect) > 0)
  {
    vuln = TRUE;
    full_url = 'http:#' + get_host_ip() + ':' + port + ctrlUrl;
    report += '\nNessus found a UPnP server that implements the WFA Device profile at :\n' +
              full_url + '\n\n' +
              'We collected some data from the M1 / DeviceInfo message :\n\n' + collect;
  }
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
else security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
