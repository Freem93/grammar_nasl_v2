#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35359);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/05/24 20:37:08 $");

  script_name(english:"HDHomeRun Discovery Service Detection");
  script_summary(english:"Simulates 'hdhomerun_config discover'");

 script_set_attribute(attribute:"synopsis", value:
"A home entertainment-related service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service implements HDHomeRun's discovery service. 
HDHomeRun is a device for streaming digital TV signals over a network,
and its discovery service allows software such as Windows Media Center
or MythTV to locate such devices." );
 script_set_attribute(attribute:"see_also", value:"http://www.silicondust.com/" );
 script_set_attribute(attribute:"solution", value:
"Ensure that use of this device is in agreement with your
organization's acceptable use and security policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


port = 65001;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


function calc_crc(data)
{
  local_var crc, i, l, x;

  crc = 0xFFFFFFFF;
  l = strlen(data);
  for (i=0; i<l; i++)
  {
    x = (crc & 0xff) ^ ord(data[i]);
    crc = crc >>> 8;
    if (x & 0x01) crc = crc ^ 0x77073096;
    if (x & 0x02) crc = crc ^ 0xEE0E612C;
    if (x & 0x04) crc = crc ^ 0x076DC419;
    if (x & 0x08) crc = crc ^ 0x0EDB8832;
    if (x & 0x10) crc = crc ^ 0x1DB71064;
    if (x & 0x20) crc = crc ^ 0x3B6E20C8;
    if (x & 0x40) crc = crc ^ 0x76DC4190;
    if (x & 0x80) crc = crc ^ 0xEDB88320;
  }
  return crc ^ 0xFFFFFFFF;
}


# Send a discovery request.
req =
  mkbyte(1) +                          # HDHOMERUN_TAG_DEVICE_TYPE
    mkbyte(4) +                        #   length
    mkdword(1) +                       #   value (1 => HDHOMERUN_DEVICE_TYPE_TUNER)
  mkbyte(2) +                          # HDHOMERUN_TAG_DEVICE_ID
    mkbyte(4) +                        #   length
    mkdword(0xffffffff);               #   value (-1 => HDHOMERUN_DEVICE_ID_WILDCARD)
req = 
  mkword(2) +                          # HDHOMERUN_TYPE_DISCOVER_REQ
  mkword(strlen(req)) +                # length
  req;
crc = calc_crc(data:req);
req +=
  mkbyte(crc >> 0) +
  mkbyte(crc >> 8) +
  mkbyte(crc >> 16) +
  mkbyte(crc >> 24);
send(socket:soc, data:req);

res = recv(socket:soc, length:20, min:20);
close(soc);


# If...
if (
  strlen(res) == 20 &&
  # the message is a reply and...
  getword(blob:res, pos:0) == 3 &&
  # the message length is correct
  getword(blob:res, pos:2) == strlen(res)-8
)
{
  # Register the service.
  register_service(port:port, ipproto:"udp", proto:"hdhomerun_discovery");

  # Collect some info for the report.
  i = 4;
  while (i < strlen(res))
  {
    tag = getbyte(blob:res, pos:i);
    len = getbyte(blob:res, pos:i+1);
    val = hexstr(substr(res, i+2, i+2+len-1));
    if (tag == 1)
    {
      if (val == '00000001')
        info += '  Device Type : TV Tuner\n';
      else
        info += '  Device Type : unknown (' + val + ')\n';
    }
    else if (tag == 2) 
    {
      info += '  Device ID   : ' + val + '\n';
    }
    i += 2 + len;
  }  
  if (report_verbosity > 0 && info)
  {
    report = string(
      "\n",
      info
    );
    security_note(port:port, extra:report, proto:"udp");
  }
  else security_note(port:port, proto:"udp");
}
