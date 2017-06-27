#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45609);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"Internet Cache Protocol (ICP) Version 2 Detection");
  script_summary(english:"Sends an ICP_OP_QUERY request");

  script_set_attribute(
    attribute:"synopsis", 
    value:"An HTTP caching service is listening on the remote port."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service supports version 2 of the Internet Cache Protocol
(ICP), used for communicating between web caches."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/rfc2186"
  );
  script_set_attribute(attribute:"solution", 
    value:"Limit access to this port if desired."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/23");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");


port = 3130;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
if (known_service(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port "+port+" is already known.");


soc = open_sock_udp(port);
if (!soc) exit(1, "Can't open socket on UDP port "+port+".");


set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Send a ICP_OP_QUERY request.
#
# - constants related to the request.
opcode = 1;
version = 2;
req_no = rand() % 1024;
req_no = 0x1234;
options = 0;
option_data = 0;

url = "http://www.nessus.org/";

# - assemble the request.
payload = ipaddr(this_host()) +
  url + mkbyte(0);

req = mkbyte(opcode) + mkbyte(version) + mkword(20+strlen(payload)) +
        mkdword(req_no) +
        mkdword(options) +
        mkdword(option_data) +
        ipaddr(this_host()) +
      payload;

# - send it and read the response.
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);
if (strlen(res) == 0) exit(0, "The service on UDP port "+port+" failed to respond.");


# If it looks like a response to our request...
if (
  strlen(res) >= 20 &&
  strlen(res) == getword(blob:res, pos:2) &&
  getdword(blob:res, pos:4) == req_no &&
  substr_at_offset(str:res, blob:url, offset:20)
)
{
  # If the response looks ok...
  opcode = getbyte(blob:res, pos:0);
  if (
    (opcode >= 2 && response <= 4) ||
    (opcode >= 21 && response <= 23)
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"udp", proto:"icpv2");
    security_note(port:port, proto:"udp");
    exit(0);
  }
  else exit(1, "The response from the service listening on port "+port+" does not look like an ICP_OP_QUERY response.");
}
else exit(0, "The response from the service listening on port "+port+" does not agree with the ICP specification.");
