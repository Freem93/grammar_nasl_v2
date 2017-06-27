#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33482);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:".NET NegotiateStream Server Detection");
  script_summary(english:"Sends a HandshakeInProgress Handshake message");

 script_set_attribute(attribute:"synopsis", value:
"A tunneling service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote server supports Microsoft's .NET NegotiateStream protocol,
which provides a lightweight authentication and security mechanism
between a client and a server when the client or server needs direct
access to the TCP stream." );
 script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/en-us/library/cc236723.aspx" );
 script_set_attribute(attribute:"solution", value:
"Limit access to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");

if (!thorough_tests || get_kb_item("global_settings/disable_service_discovery")  ) exit(0);
port = get_unknown_svc(0);              # nb: no default
if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a HandshakeInProgress Handshake message.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

authpayload = "";

req = 
  mkbyte(0x16) +                       # MessageId
  mkbyte(1) +                          # MajorVersion
  mkbyte(0) +                          # MinorVersion
  mkword(strlen(authpayload)) +        # payload size
  authpayload;
send(socket:soc, data:req);
res = recv(socket:soc, length:128);
close(soc);


# If...
if (
  # it's a HandshakeError and...
  getbyte(blob:res, pos:0) == 0x15 &&
  # the version is 1.0 and...
  getbyte(blob:res, pos:1) == 1 &&
  getbyte(blob:res, pos:2) == 0 &&
  # we have a logon failure
  (
    getdword(blob:res, pos:5) == 0x6fe ||
    getdword(blob:res, pos:9) == 0x6fe ||
    "Authentication failure" >< res
  )
)
{
  # Register and report the service.
  register_service(port:port, proto:"negotiatestream");
  security_note(port);
}
