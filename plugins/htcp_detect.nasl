#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45608);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"Hyper Text Caching Protocol (HTCP) Detection");
  script_summary(english:"Sends a TST request");

  script_set_attribute(
    attribute:"synopsis", 
    value:"An HTTP caching service is listening on the remote port."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service supports the Hyper Text Caching Protocol (HTCP), 
used for discovering HTTP caches and cached data, managing sets of 
HTTP caches, and monitoring cache activity."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tools.ietf.org/html/rfc2756"
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
include("byte_func.inc");
include("misc_func.inc");


port = 4827;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
if (known_service(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port "+port+" is already known.");


soc = open_sock_udp(port);
if (!soc) exit(1, "Can't open socket on UDP port "+port+".");


set_byte_order(BYTE_ORDER_BIG_ENDIAN);

ver_major = 0;
ver_minor = 0;


# Send a TST request.
#
# - constants related to the TST request.
opcode = 1;
f1 = 1;
rr = 0;
trans_id = rand() % 1024;

method = "GET";
uri = "http://www.nessus.org/";
version = "HTTP/1.1";
req_hdrs = 'Accept-Language: en\r\n';

# - assemble the request.
opdata = 
  mkword(strlen(method)) + method + 
  mkword(strlen(uri)) + uri + 
  mkword(strlen(version)) + version +
  mkword(strlen(req_hdrs)) + req_hdrs;

data = mkbyte(opcode) + mkbyte((f1 << 6) | (rr << 7)) + 
  mkdword(trans_id) + opdata;
data = mkword(strlen(data)+2) + data;

auth = mkword(2);

req = mkword(4+strlen(data+auth)) + mkbyte(ver_major) + mkbyte(ver_minor) + 
    data +
    auth;

# - send it and read the response.
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);
if (strlen(res) == 0) exit(0, "The service on UDP port "+port+" failed to respond.");

# If it looks like a response to our opcode...
if (
  strlen(res) > 6 &&
  strlen(res) == getword(blob:res, pos:0) &&
  (getbyte(blob:res, pos:6) & 0x0f) == opcode
)
{
  # If the response looks ok...
  response = getbyte(blob:res, pos:6) >> 4;
  f1 = (getbyte(blob:res, pos:7) >> 6) & 1;
  rr = (getbyte(blob:res, pos:7) >> 7) & 1;

  if (
    rr == 1 &&
    (
      (f1 == 0 && (response >= 0 && response <= 1)) ||
      (f1 == 1 && (response >= 0 && response <= 5))
    )
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"udp", proto:"htcp");
    security_note(port:port, proto:"udp");
    exit(0);
  }
  else exit(1, "The response from the service listening on port "+port+" does not look like a TST response.");
}
else exit(0, "The response from the service listening on port "+port+" does not agree with the HTCP specification.");
