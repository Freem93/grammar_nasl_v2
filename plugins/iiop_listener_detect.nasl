#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20734);
  script_version("$Revision: 1.11 $");

  script_name(english:"CORBA IIOP Listener Detection");
  script_summary(english:"Detects a CORBA IIOP listener");

 script_set_attribute(attribute:"synopsis", value:
"There is a CORBA IIOP listener active on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a CORBA Internet Inter-ORB Protocol (IIOP)
listener on the specified port.  CORBA is a vendor-independent
architecture for applications that work together, and IIOP is a
protocol by which such applications can communicate over TCP/IP." );
 script_set_attribute(attribute:"see_also", value:"http://www.omg.org/cgi-bin/doc?formal/04-03-01" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/17");
 script_cvs_date("$Date: 2011/03/11 21:18:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 683);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


function put_data(data)
{
 local_var len;

 len = strlen(data);

 if (len % 4)
   data += crap(data:mkbyte(0), length:4-(len%4));

 return mkdword(len) + data;
}


function put_string(s)
{
 return put_data(data:s+mkbyte(0));
}



if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(683);
  if (!port) exit(0);
}
else port = 683;
if (!get_tcp_port_state(port)) exit(0);


# Send a bogus request.
soc = open_sock_tcp(port);
if (!soc) exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = 
	mkdword(0) + # service context list
	mkdword(1) + # request id
	mkdword(1) + # response expected
	put_data(data:rand_str(length:6)) +
	put_string(s:"get") +
	mkdword(0) ; # requesting principal length


req = 
	"GIOP" +    # magic
	mkword(1) + # GIOP version (1.0)
	mkbyte(1) + # byte order (little-endian)
	mkbyte(0) + # message type (request)
	mkdword(strlen(req)) + # message length
	req;
	
send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:1024);

close(soc);
if (isnull(res)) exit(0);


# It's IIOP if...
if (
  # the response is long enough and...
  strlen(res) >= 12 &&
  # it has the magic string "GIOP" and is for version 1.0 and...
  substr(res, 0, 5) == raw_string("GIOP", 0x01, 0x00) &&
  # it's a reply.
  ord(res[7]) == 1
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"corba-iiop");

  security_note(port);
}
