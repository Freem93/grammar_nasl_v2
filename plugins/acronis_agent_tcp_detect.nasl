#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31644);
  script_version("$Revision: 1.6 $");

  script_name(english:"Acronis Agent Detection (TCP)");
  script_summary(english:"Simulates a new remote management connection");

 script_set_attribute(attribute:"synopsis", value:
"A backup service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an Acronis Agent, a component of Acronis
TrueImage that allows for managing backup and restore operations on
the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.acronis.com/enterprise/products/ATIES/windows-agent.html" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/25");
 script_cvs_date("$Date: 2011/03/11 21:18:07 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9876);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(9876);
  if (!port) exit(0, "There are no unknown services.");
  if (!silent_service(port)) exit(0, "The service listening on port "+port+" is not silent."); 
}
else port = 9876;

if (! service_is_unknown(port:port))
 exit(0, "The service on port "+port+" is already known.");
if (!get_tcp_port_state(port)) exit(0, "TCP port "+port+" is closed.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "TCP connection failed to port "+port+".");


# Simulate a new remote management connection.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = mkword(2) + mkword(1) + mkbyte(0);
req = mkdword(strlen(req)) + req;
send(socket:soc, data:req);

# If the result is a dword and equal to 6...
res = recv(socket:soc, length:4);
if (strlen(res) == 4 && getdword(blob:res, pos:0) == 6)
{
  # Read the rest of the packet but allow for more as an additional check.
  res = recv(socket:soc, length:32);

  # If...
  if (
    # the packet length was as anticipated and...
    strlen(res) == 6 && 
    # the first two words equal 2 and...
    getword(blob:res, pos:0) == 2 &&
    getword(blob:res, pos:2) == 2 &&
    # the connection was either...
    (
      # rejected (password required?) or...
      getword(blob:res, pos:4) == 0 ||
      # successful
      getword(blob:res, pos:4) == 0x100
    )
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"acronis_agent");
    security_note(port);
  }
}

close(soc);
