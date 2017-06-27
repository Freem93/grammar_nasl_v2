#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35360);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/22 21:12:16 $");

  script_name(english:"HDHomeRun Control Service Detection");
  script_summary(english:"Sends a request to get the system version (and model)");

 script_set_attribute(attribute:"synopsis", value:
"A home entertainment-related service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service implements HDHomeRun's control service.  HDHomeRun
is a device for streaming digital TV signals over a network, and its
control service provides a way for software to manage the device, not
only programs it streams but also its firmware." );
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

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 65001);

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(65001);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 65001;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


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


# Request various info.
info = "";
sys_vars = make_list("/sys/model", "/sys/version");

foreach sys_var (sys_vars)
{
  soc = open_sock_tcp(port);
  if (!soc) break;

  req =
    mkbyte(3) +                          # HDHOMERUN_TAG_GETSET_NAME
      mkbyte(strlen(sys_var)+1) +        #   length
      sys_var + mkbyte(0);
  req = 
    mkword(4) +                          # HDHOMERUN_TYPE_GETSET_REQ
    mkword(strlen(req)) +                # length
    req;
  crc = calc_crc(data:req);
  req +=
    mkbyte(crc >> 0) +
    mkbyte(crc >> 8) +
    mkbyte(crc >> 16) +
    mkbyte(crc >> 24);
  send(socket:soc, data:req);

  res_1 = recv(socket:soc, length:4, min:4);
  if (
    strlen(res_1) == 4 && 
    getword(blob:res_1, pos:0) == 5
  )
  {
    len = getword(blob:res_1, pos:2);
    res_2 = recv(socket:soc, length:len+4);

    # If ...
    if (
      # the payload length is correct and...
      strlen(res_2) == len+4 &&
      # it's a response to our request
      (mkbyte(3)+mkbyte(strlen(sys_var)+1)+sys_var+mkbyte(0)) >< res_2
    )
    {
      # Make sure the CRC is correct.
      crc_pkt = substr(res_2, len);
      crc_calc = calc_crc(data:substr(res_1+res_2, 0, 4+len-1));
      if (mkbyte(crc_calc >> 0) + mkbyte(crc_calc >> 8) + mkbyte(crc_calc >> 16) + mkbyte(crc_calc >> 24) == crc_pkt)
      {
        i = 0;
        while (i < strlen(res_2))
        {
          tag = getbyte(blob:res_2, pos:i);
          len = getbyte(blob:res_2, pos:i+1);
          if (tag == 4)
          {
            val = substr(res_2, i+2, i+2+len-2);

            if ("model" >< sys_var) dev_info = "Model";
            else if ("version" >< sys_var) dev_info = "Version";

            info += '  ' + dev_info + crap(data:' ', length:7-strlen(dev_info)) + ' : ' + val + '\n';
          }
          i += 2 + len;
        }
      }  
    }
  }
  close(soc);
}


if (info)
{
  # Register and report the service.
  register_service(port:port, proto:"hdhomerun_control");

  if (report_verbosity > 0 && info)
  {
    report = string(
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
