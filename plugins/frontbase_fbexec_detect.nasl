#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24898);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/05/31 21:45:42 $");

  script_name(english:"FrontBase FBExec Process Detection");
  script_summary(english:"Tries to initialize a connection to a FrontBase database");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"There is a FrontBase FBExec process listening on the remote host. 
This service brokers connections from network clients to FrontBase database processes
running on the remote host." );
 # http://web.archive.org/web/20070312171430/http://www.frontbase.com/cgi-bin/WebObjects/FrontBase
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa0035ed" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port to hosts that need to access
the database." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 20020);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(20020);
  if (!port) exit(0);
}
else port = 20020;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to establish a connection to FBExec.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
db = SCRIPT_NAME;

req = "1$any client$" + get_host_name() + "$0$0";
req = mkdword(strlen(req)) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# If the response looks ok...
if (
  strlen(res) == 5 && 
  getdword(blob:res, pos:0) == 1 && 
  substr(res, 4) == "0"
)
{
  # Now start a connection to a database.
  req = "6$" + db;
  req = mkdword(strlen(req)) + req;
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);

  # If the response indicates the database...
  if (
    # exists or..
    (
      strlen(res) == 7 && 
      getdword(blob:res, pos:0) == 3 && 
      substr(res, 4) == "0$2"
    ) ||
    # doesn't exist.
    (
      strlen(res) == 8 && 
      getdword(blob:res, pos:0) == 4 && 
      substr(res, 4) == "0$-1"
    )
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"frontbase_fbexec");
    security_note(port);
  }
}
close(soc);

