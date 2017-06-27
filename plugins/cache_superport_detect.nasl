#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25934);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/01/13 16:27:52 $");

  script_name(english:"Cache' SuperServer Detection");
  script_summary(english:"Tries to detect Cache' SuperServer");

  script_set_attribute(attribute:"synopsis", value:"A database service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a Cache' server, sometimes refered to as a Cache'
SuperServer.  Cache' is an object database often used in association
with web applications, and the SuperServer listens for incoming
connections and dispatches them to the appropriate subsystem.");
  script_set_attribute(attribute:"see_also", value:"http://www.intersystems.com/cache/index.html");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1972);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(1972);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else port = 1972;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


global_var unicode;

function put_string(string)
{
  local_var i, len, null, res;

  null = mkbyte(0);
  res = "";

  if (unicode == TRUE)
  {
    len = strlen(string);
    for (i=0; i<len; i++)
    {
       res += string[i] + null;
    }
  }
  else res = string;

  res = mkbyte(strlen(res)+2) + mkbyte(2) + res;

  return res;
}


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

ns = "USER";
db_user = crap(5);                     # database user (encrypted)
db_pass = crap(6);                     # database pass (encrypted)
user = "Nessus";                       # user running the "program"
host = this_host_name();               # host on which the "program" runs
prog = SCRIPT_NAME;                    # name of the "program"

unicode = FALSE;


# Try to simulate a login from Studio.
#
# - initial request.
seq = 1;
req = mkbyte(0x2a) + mkbyte(0x00);
req = mkdword(strlen(req)) +
  mkdword(seq) +
  mkdword(0x00) +
  mkbyte(0x48) +
  mkbyte(0x53) +
  req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# If...
if (
  # the response is long-enough and...
  strlen(res) >= 14 &&
  # the initial dword is the packet length and...
  getdword(blob:res, pos:0) + 14 == strlen(res) &&
  # the sequence number matches
  getdword(blob:res, pos:4) == seq
)
{
  if (mkbyte(0x09) + mkbyte(0x01) + "Unicode" >< res) unicode = TRUE;

  # - actual login
  ++seq;
  req =
    put_string(string:ns) +
    put_string(string:db_user) +
    put_string(string:db_pass) +
    put_string(string:user) +
    put_string(string:host) +
    put_string(string:prog) +
    mkbyte(0x0e) +
      mkbyte(0x01) +
      mkdword(0x05) +
      mkdword(0x02) +
      mkbyte(0xce) +
      mkbyte(0x0e) +
      mkbyte(0x00) +
      mkbyte(0x00) +
    put_string(string:this_host()) +
    mkbyte(0x03) +
      mkbyte(0x01) +
      mkbyte(0x00) +
    mkbyte(0x03) +
      mkbyte(0x04) +
      mkbyte(0x01) +
    mkbyte(0x02) +
    mkbyte(0x04);
  req = mkdword(strlen(req)) +
    mkdword(seq) +
    mkdword(0x00) +
    mkbyte(0x43) +
    mkbyte(0x4e) +
    req;
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  close(soc);

  # If..
  if (
    # the response is long-enough and...
    strlen(res) >= 14 &&
    # the initial dword is the packet length and...
    getdword(blob:res, pos:0) + 14 == strlen(res) &&
    # the sequence number matches and ...
    getdword(blob:res, pos:4) == seq &&
    # either
    (
      # the login failed or...
      mkbyte(1) + "Access Denied" >< res ||
      # the login succeeded
      mkbyte(1) + "Cache Objects Version" >< res
    )
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"cache_superserver");
    security_note(port);
  }
}
