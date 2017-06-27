#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29994);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/12/19 23:04:05 $");

  script_name(english:"LANDesk Management Agent Detection");
  script_summary(english:"Pings an agent");

  script_set_attribute(attribute:"synopsis", value:
"An asset management agent is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a LANDesk Management Agent, one of the
components of LANDesk Management Suite installed on 
managed clients for communicating with the administrative
console.");
  # http://web.archive.org/web/20090503002610/http://www.landesk.com/SolutionServices/product.aspx?id=716
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae87ac86");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  exit(0);
}

#

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 9595;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


# Try to ping the agent.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = 
  "PDSV" + mkword(4) + mkdword(1) +
  "ININ" + mkword(4) + mkdword(1) +
  "APID" + mkword(4) +
  "IUSRRPLD" + mkword(4) +
  mkdword(0x64);
req = "PING" + mkword(strlen(req)) + req;
send(socket:soc, data:req);

res_1 = recv(socket:soc, length:6);
if (strlen(res_1) != 6) exit(0);
if (substr(res_1, 0, 3) != "ping") exit(0);
len = getword(blob:res_1, pos:4);
if (len == 0) exit(0);
res_2 = recv(socket:soc, length:len);
if (strlen(res_2) != len) exit(0);
res = res_1 + res_2;

# If the response looks right
if ("PDSV" >< res && "MAID" >< res)
{
  # Extract some interesting info.
  info = "";
  # - device ID.
  i = stridx(res, "MAID"+mkword(16));
  if (i > -1)
  {
    id = hexstr(substr(res, i+6,  i+9)) + '-' +
         hexstr(substr(res, i+10, i+11)) + '-' +
         hexstr(substr(res, i+12, i+13)) + '-' +
         hexstr(substr(res, i+14, i+15)) + '-' +
         hexstr(substr(res, i+16, i+21));
    id = toupper(id);
    info += '  Device ID    : {' + id + '}\n';
  }
  # - Group.
  i = stridx(res, "AGRP");
  if (i > -1)
  {
    l = getword(blob:res, pos:i+4);
    --l;
    group = substr(res, i+6,  i+6+l-1);
    info += '  Workgroup    : ' + group + '\n';
  }
  # - OS info.
  i = stridx(res, "OSVR"+mkword(4));
  if (i > -1)
  {
    ver = getbyte(blob:res, pos:i+9) + "." +
          getbyte(blob:res, pos:i+8);
    build = getword(blob:res, pos:i+6);
    info += '  OS Version   : ' + ver + '\n';
    info += '  OS Build     : ' + build + '\n';
  }
  # - MAC address.
  i = stridx(res, "MACA"+mkword(6));
  if (i > -1)
  {
    mac = hexstr(substr(res, i+6,  i+11));
    mac= toupper(mac);
    info += '  MAC Address  : ' + mac + '\n';
  }
  # - network address / mask.
  i = stridx(res, "MASK"+mkword(8));
  if (i > -1)
  {
    mask = getbyte(blob:res, pos:i+6) + '.' +
           getbyte(blob:res, pos:i+7) + '.' +
           getbyte(blob:res, pos:i+8) + '.' +
           getbyte(blob:res, pos:i+9);
    mask= toupper(mask);
    info += '  Network mask : ' + mask + '\n';
  }

  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"landesk_residentagent");

  if (report_verbosity)
  {
    report = string(
      "\n",
      "Here is some information collected from the remote LANDesk Management\n",
      "Agent :\n",
      "\n",
      info
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
