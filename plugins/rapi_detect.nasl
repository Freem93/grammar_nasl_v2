#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31412);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_name(english:"RAPI Manager Detection");
  script_summary(english:"Initiates a connection and requests the ActiveSync version");

 script_set_attribute(attribute:"synopsis", value:
"A synchronization service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the Remote Applications Programming
Interfaces (RAPI) protocol and is used by the host to manage
connections from Windows Mobile / Windows CE devices." );
 script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/library/aa513321.aspx" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 990);

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
  port = get_unknown_svc(990);
  if (!port) exit(0);
  if (silent_service(port)) exit(0);
}
else port = 990;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Initiate a connection.
req = mkdword(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:5, min:4);
if (strlen(res) != 4 || mkdword(3) != res) exit(0);


# Request ActiveSync version.
req = mkdword(6);
send(socket:soc, data:req);
res = recv(socket:soc, length:17, min:16);
close(soc);


# If...
if (
  # it holds 4 dwords and...
  strlen(res) == 16 &&
  # it's a protocol version response and...
  getdword(blob:res, pos:0) == 7 &&
  getdword(blob:res, pos:4) == 8 &&
  # the protocol seems reasonable
  getdword(blob:res, pos:8) < 99
)
{
  # Register / report the service.
  register_service(port:port, proto:"rapi_manager");

  proto = string(getdword(blob:res, pos:8), ".", getdword(blob:res, pos:12));
  set_kb_item(name:"RAPI/"+port+"/ActiveSync_Version", value:proto);

  if (info && report_verbosity)
  {
    report = string(
      "\n",
      "The remote service supports ActiveSync version ", proto, ".\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

}
