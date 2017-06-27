#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56195);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/02/27 22:06:59 $");

  script_name(english:"Bitcoin Detection");
  script_summary(english:"Sends a version message");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"A peer-to-peer electronic currency service is listening on this
port."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service is a Bitcoin node.  Bitcoin is an open source,
peer-to-peer digital currency, and a Bitcoin node is used by a
client to communicate with other peers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.bitcoin.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Make sure that the use of this program agrees with your
organization's acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 8333);

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
  port = get_unknown_svc(8333);
  if (!port) exit(0, "There are no unknown services.");
  if (!silent_service(port)) exit(0, "The service listening on port "+port+" is not silent.");
}
else port = 8333;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");


function mkipaddr()
{
  local_var ip, str;

  ip = _FCT_ANON_ARGS[0];
  str = split(ip, sep:'.', keep:FALSE);

  return mkbyte(int(str[0])) +
    mkbyte(int(str[1])) +
    mkbyte(int(str[2])) +
    mkbyte(int(str[3]));
}


# Define some variables.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

sport = get_source_port(soc);

addr_me =
  mkdword(1) + mkdword(0) + mkdword(0) + mkdword(0) + mkdword(0xFFFF0000) +
  mkipaddr(this_host()) +
  mkbyte(sport >> 8) + mkbyte(sport & 0xff);
addr_you = 
  mkdword(1) + mkdword(0) + mkdword(0) + mkdword(0) + mkdword(0xFFFF0000) +
  mkipaddr(get_host_ip()) +
  mkbyte(port >> 8) + mkbyte(port & 0xff);

cmd = "version";
cmd += crap(data:mkbyte(0), length:12-strlen(cmd));
magic_main = 0xD9B4BEF9;
magic_testnet = 0xDAB5BFFA;
start_height = rand() % 1024;


# Send a 'version' request.
payload = 
  mkdword(31900) +                     # client version (31900 => "0.3.19")
  mkdword(1) + mkdword(0) +            # services (1 => NODE_NETWORK services)
  mkdword(unixtime()) + mkdword(0) +   # timestamp
  addr_you +                           # addr_you (target's network address)
  addr_me +                            # addr_me (scanner's network address)
  mkdword(rand()) + mkdword(rand()) +  # nonce
  mkbyte(0) +                          # subversion
  mkdword(start_height);               # start_height (last block received by emitting node)
req = 
  mkdword(magic_main) +                # magic
  cmd +                                # command (padded to 12 chars)
  mkdword(strlen(payload)) +           # length
  payload;
send(socket:soc, data:req);

res_1 = recv(socket:soc, length:20, min:20);
if (strlen(res_1) == 0) exit(0, "The service on port "+port+" failed to respond.");
if (strlen(res_1) != 20) exit(0, "Failed to read 20 bytes from the service on port "+port+".");

if (
  substr(res_1, 4, 15) != cmd ||
  (
    getdword(blob:res_1, pos:0) != magic_main &&
    getdword(blob:res_1, pos:0) != magic_testnet
  )
) exit(0, "The response from the service on port "+port+" does not look like it's from Bitcoin.");


# Let's read the client's 'version' response to make sure 
# we're not just seeing our output echoed back.
len = getdword(blob:res_1, pos:16);
res_2 = recv(socket:soc, length:len, min:len);
if (strlen(res_2) == 0) exit(0, "The service on port "+port+" failed to respond with its version.");
if (strlen(res_2) != len) exit(0, "Failed to read "+len+" bytes from the service on port "+port+".");
if (res_2 == payload) exit(0, "The service on port "+port+" is not Bitcoin as it echoed back the payload.");


# Determine the client's version.
nversion = getdword(blob:res_2, pos:0);
if (nversion % 100 == 0)
  version = strcat(
    nversion/1000000, '.', 
    (nversion/10000)%100, '.',
    (nversion/100)%100
  );
else
  version = strcat(
    nversion/1000000, '.', 
    (nversion/10000)%100, '.',
    (nversion/100)%100, '.',
    nversion % 100
  );



# Register and report the service.
register_service(port:port, proto:"bitcoin");
set_kb_item(name:"bitcoin/"+port+"/version", value:version);

if (report_verbosity > 0)
{
  report = '\n  Version : ' + version + 
           '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
