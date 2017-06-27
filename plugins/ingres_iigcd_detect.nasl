#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25636);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:"Ingres Data Access Server Detection");
  script_summary(english:"Tries to log in to Ingres Data Access Server");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an Ingres Data Access Server, which translates requests 
from the JDBC driver and .NET Data Provider into an internal format and forwards
them to the appropriate DBMS server." );
 script_set_attribute(attribute:"see_also", value:"http://docs.ingres.com/connectivity/toc" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 21071);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(21071);
  if (!port) exit(0);
}
else port = 21071;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


uid = "nessus";
db = "demodb";
user = SCRIPT_NAME;
my_host = this_host_name();
my_ip = this_host();
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Try to initiate a connection.
init = 
  "JCTLCR" + 
  raw_string(0x01, 0x01, 0x02, 0x02, 0x01, 0x0f, 0x06, 0x04) +
  "DMML" +
  raw_string(
    0x03, 0x0d, 0x01, 0x01, 0x06, 0x03, 0x08, 0xb8,
    0x97, 0xc4, 0xdf, 0x07, 0x89, 0xe3, 0xf1
  );
send(socket:soc, data:mkword(strlen(init)+2)+init);
res = recv(socket:soc, length:256, min:2);


# If it looks like that worked because...
if (
  # the word at the first byte is the packet length and...
  strlen(res) > 8 && getword(blob:res, pos:0) == strlen(res) &&
  # the string after the packet length looks right and...
  stridx(res, "JCTLCC") == 2 &&
  # we see "DMML" in the output
  "DMML" >< res
) 
{
  # Try to log in.
  req = 
    "DMTLDTDMML" +                     # magic?
    mkword(strlen(db+uid+user+my_host+my_ip)+37) +
    raw_string(0x01, 0x03) +           # ?
    mkword(0x01) +                     # database
      mkword(strlen(db)) + db +
    mkword(0x02) +                     # db username 
      mkword(strlen(uid)) + uid +
    mkword(0x03) +                     # encrypted password
      mkword(0x08) + 
      raw_string(0xc8, 0xb6, 0xd1, 0x7e, 0x65, 0x26, 0x56, 0xcb) +
    raw_string(                        # ?
      0x10, 0x00, 0x01, 0x00, 0x01
    ) +
    mkword(0x11) +                     # account username on client
      mkword(strlen(user)) + user +
    mkword(0x12) +                     # client hostname
      mkword(strlen(my_host)) + my_host +
    mkword(0x13) +                     # client ip
      mkword(strlen(my_ip)) + my_ip;
  send(socket:soc, data:mkword(strlen(req)+2)+req);
  res = recv(socket:soc, length:256, min:2);

  # If it looks like a valid response because...
  if (
    # the word at the first byte is the packet length and...
    strlen(res) > 8 && getword(blob:res, pos:0) == strlen(res) &&
    (
      # either the server shut down the connection or...
      stridx(res, "DMTLDR") == 2 ||
      (
        # the string after the packet length looks right and...
        stridx(res, "DMTLDTDMML") == 2 &&
        # we see "DMML" in the output
        "DMML" >< res
      )
    )
  )
  {
    # Shut down the connection cleanly unless the server's already done that.
    if ("DMTLDR" >!< res)
    {
      req = "DMTLDR";
      send(socket:soc, data:mkword(strlen(req)+2)+req);
      res = recv(socket:soc, length:256, min:2);
    }

    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"iigcd");
    security_note(port);
  }
}
close(soc);
