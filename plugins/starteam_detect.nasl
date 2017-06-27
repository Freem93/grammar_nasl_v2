#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31355);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"StarTeam Server Detection");
  script_summary(english:"Sends a SRVR_CMD_GET_SERVER_PARAMS request");

 script_set_attribute(attribute:"synopsis", value:
"A software configuration management (SCM) service is listening on the
remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Borland StarTeam Server.  StarTeam is a
commercial software configuration and change management tool." );
 script_set_attribute(attribute:"see_also", value:"http://www.borland.com/starteam/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 49201);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(49201);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 49201;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send an SRVR_CMD_GET_SERVER_PARAMS request.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

magic = "Alan";
id = 
  mkword(100) +                         #   revision level
  crap(data:mkbyte(0), length:16) +     #   client id
  mkdword(0) +                          #   connect id
  mkdword(0) +                          #   component id
  mkdword(3) +                          #   command id (3 => SRVR_CMD_GET_SERVER_PARAMS)
  mkdword(0) +                          #   command time
  mkdword(0);                           #   command user id
data = mkdword(-1);
req = 
                                        # Message Data Header
  mkdword(0) +                          #   session tag
  mkdword(unixtime()) +                 #   client timestamp
  mkdword(0x10000000) +                 #   flags (|1 for zlib)
  mkdword(0) +                          #   key id
  mkdword(0) +                          #   reserved
                                        # Packet Header
  magic +                               #   signature
  mkdword(strlen(id+data)) +            #   packet size
  mkdword(strlen(id+data)) +            #   data size
  mkdword(8) +                          #   flags
                                        # ID
  id +
                                        # Data
  data;
send(socket:soc, data:req);
res = recv(socket:soc, length:256, min:16);
close(soc);


# Register / report the service if it looks like a StarTeam reply.
if (
  strlen(res) >= 16 && 
  stridx(res, magic) == 0 &&
  getdword(blob:res, pos:4) == strlen(res) - 16
)
{
  # Gather some info.
  info = "";

  i = 0x24;
  if (strlen(res) >= i+4)
  {
    l = getdword(blob:res, pos:i);
    if (l > 0)
    {
      build = substr(res, i+4, i+l+4-1);
      # nb: I'm not sure if a version consists solely of digits and dots.
      if (build =~ "^[0-9][0-9.]+")
      {
        set_kb_item(name:"StarTeam/"+port+"/Build", value:build);
        info += '  Server Build : ' + build + '\n';
      }
    }
    i += 4 + l;
  }
  if (strlen(res) >= i+4)
  {
    l = getdword(blob:res, pos:i);
    if (l > 0)
    {
      prod = substr(res, i+4, i+l+4-1);
      set_kb_item(name:"StarTeam/"+port+"/Product", value:prod);
      info += '  Product      : ' + prod + '\n';
    }
    i += 4 + l;
  }
  if (strlen(res) >= i+4)
  {
    l = getdword(blob:res, pos:i);
    if (l > 0)
    {
      # I have no idea what this is at the moment.
      x = substr(res, i+4, i+l+4-1);
    }
    i += 4 + l;
  }

  # Register and report the service.
  register_service(port:port, proto:"starteam_server");

  if (info && report_verbosity)
  {
    report = string(
      "\n",
      "Here is some information about the remote StarTeam server that Nessus\n",
      "was able to collect :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
