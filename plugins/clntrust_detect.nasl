#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27600);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2011/05/24 20:37:07 $");

  script_name(english:"Novell CLNTRUST Service Detection");
  script_summary(english:"Sends an authentication service request");

 script_set_attribute(attribute:"synopsis", value:
"A single-signon service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CLNTRUST (client trust), a component used
by Novell's BorderManager for authentication to its proxy service." );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/coolsolutions/tip/7761.html" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port to hosts running BorderManager." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_exclude_keys("Known/udp/3024");
  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 3024;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


function add_nulls(str)
{
  local_var i, res;

  res = NULL;
  for (i=0; i<strlen(str); i++)
    res += str[i] + raw_string(0x00);
  return res;
}


# Send an authentication request.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

magic = rand() % 0xffff;
tree = "NESSUS";
user = tree + '\\' + 27600;

req = 
  mkdword(0x11111111) +
  mkdword(magic) +
  mkdword(0x2a) +
  mkdword(0x06) +
  add_nulls(str:"\") +
  add_nulls(str:tree) +
  add_nulls(str:"\") +
  add_nulls(str:user);
send(socket:soc, data:req);
res = recv(socket:soc, length:64, min:8);
close(soc);


# Register and report the service if...
if (
  # the response is long-enough and...
  strlen(res) == 8 &&
  # the packet looks right
  getdword(blob:res, pos:0) == 0x22222222 &&
  getdword(blob:res, pos:4) == magic
)
{
  register_service(port:port, ipproto:"udp", proto:"nss_sso");
  security_note(port:port, proto:"udp");
}
