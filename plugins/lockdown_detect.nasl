#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57461);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/01 14:32:59 $");

  script_name(english:"Apple iOS Lockdown Detection");
  script_summary(english:"Tries to communicate with the lockdown service");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running Apple iOS."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The lockdown service, part of Apple iOS, was detected on the remote
host.  This service is used to communicate with iOS devices for
several tasks (e.g., Wi-Fi sync). 

Note that this plugin will only work against devices that have ever
had Wi-Fi sync enabled (iOS versions 5 and later)."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:iphone_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports(62078);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

##
# sends the given payload in the lockdown format
# (4 byte length followed by XML payload)
#
# @anonparam socket socket the packet will be written to
# @anonparam data   payload of the packet to be sent
#
# @return return value of send()
##
function _send_pkt()
{
  local_var socket, data, len, req;
  socket = _FCT_ANON_ARGS[0];
  data = _FCT_ANON_ARGS[1];
  len = strlen(data);
  req = mkdword(len) + data;
  return send(socket:socket, data:req);
}

##
# reads lockdown packet from the given socket
#
# @anonparam socket socket to read the data from
#
# @return payload of lockdown packet read from 'socket'
##
function _recv_pkt()
{
  local_var socket, len, res;
  socket = _FCT_ANON_ARGS[0];

  len = recv(socket:socket, length:4);
  if (strlen(len)< 4)
    exit(1, 'Length not received in response.');
  else
    len = getdword(blob:len, pos:0);

  res = recv(socket:socket, length:len);
  return res;
}

port = 62078;
if (!get_tcp_port_state(port)) exit(0, 'Port ' + port + ' does not appear to be open.');
if (known_service(port:port)) exit(0, 'The service on port ' + port + ' has already been identified.');

req = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>usbmuxd</string>
	<key>ProtocolVersion</key>
	<string>2</string>
	<key>Request</key>
	<string>QueryType</string>
</dict>
</plist>
';

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

_send_pkt(soc, req);
res = _recv_pkt(soc);
close(soc);

if ('<string>com.apple.mobile.lockdown</string>' >< res)
{
  set_kb_item(name:"Host/OS/iOS lockdown", value:"Apple iOS");
  set_kb_item(name:"Host/OS/iOS lockdown/Confidence", value:100);
  set_kb_item(name:"Host/OS/iOS lockdown/Type", value:"mobile");

  register_service(port:port, ipproto:"tcp", proto:"lockdown");
  security_note(port);
}
else
  exit(0, 'The lockdown service doesn\'t appear to be listening on port ' + port + '.');
