#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24018);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_name(english:"TCP Channel Detection");
  script_summary(english:"Detects a TCP Channel for .NET Remoting Services");

  script_set_attribute(attribute:"synopsis", value:"A TCP channel is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a TCP-based .NET Remoting Channel Service,
also known as a 'TCP channel'.  .NET Remoting is an API developed by
Microsoft and used for interprocess communications, and a channel
service provides the mechanism by which such communications occur.  Two
channel services are supplied as part of Microsoft's .NET Framework - a
TCP channel, which uses binary payloads, and an HTTP channel, which uses
SOAP by default.");
  script_set_attribute(attribute:"see_also", value:"http://msdn2.microsoft.com/en-us/library/72x4h507.aspx");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/.NET_Remoting");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value: "None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/remoting_tcp");

  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"remoting_tcp", exit_on_fail:TRUE);


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Define a serialized object using the binary formatter.
ns = "NessusPlugins";
class = "FooServer";
assembly = "object";
method = "BarMethod";
endpoint = "NASL";
arg = "Tenable";

typename = string(ns, ".", class, ", ", assembly);
classname = string(
  typename, ", ",
  "Version=0.0.0.0, ",
  "Culture=neutral, ",
  "PublicKeyToken=null"
);
sobj =
  raw_string(                          # header (constant?)
    0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
  ) +
  mkbyte(21) +                         # method call
    mkbyte(18) +                       #   method call flags (18 => primative args & ExcludeLogicalCallContext)
    mkbyte(0) +                        #   constant?
    mkbyte(0) +                        #   constant?
    mkbyte(0) +                        #   constant?
                                       #   method name
      mkbyte(18) +                     #     primitive type code (18 => string)
        mkbyte(strlen(method)) +       #       length
        method +                       #       string chars
                                       #   class name (namespace and assembly)
      mkbyte(18) +                     #     primitive type code (18 => string)
        mkbyte(strlen(classname)) +    #       length
        classname +                    #       string chars
  mkdword(1) +                         # number of parameters (1)
    mkbyte(18) +                       #   primitive type code (18 => string)
      mkbyte(strlen(arg)) +            #     length
      arg +                            #     string chars
  mkbyte(0x0b);                        # end


# Send an activation request.
uri = string("tcp://", get_host_name(), ":", port, "/", endpoint);
type = "application/octet-stream";

req =
  ".NET" +                             # magic
  mkword(1) + mkdword(0) +             # ?
  mkdword(strlen(sobj)) +              # length of serialized object
  mkword(4) +                          # ?
  mkbyte(1) +                          # ?
  mkbyte(1) +                          # ?
  mkdword(strlen(uri)) + uri +         # uri
  mkword(6) +                          # ?
  mkbyte(1) +                          # ?
  mkbyte(1) +                          # ?
  mkdword(strlen(type)) + type +       # mime type
  mkword(0);
send(socket:soc, data:req);
send(socket:soc, data:sobj);

res = recv(socket:soc, length:16);
if (strlen(res) == 0) audit(AUDIT_RESP_NOT, port);


# If ...
if (
  # the response is 16 bytes long and...
  strlen(res) == 16 &&
  # it starts with the magic header.
  (".NET" + mkword(1) + mkdword(2)) == substr(res, 0, 9)
)
{
  type = getword(blob:res, pos:14);

  # Read the response.
  if (type == 0)
  {
    len = getdword(blob:res, pos:10);
    res = recv(socket:soc, length:len);
  }
  else {
    res = recv(socket:soc, length:1024);
  }
  if (res == NULL) exit(0);

  # If ...
  if (
    (
      type == 0 &&
      # the response length is correct and...
      strlen(res) == len &&
      # it has a (partial) object header and...
      raw_string(0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) == substr(res, 9,16) &&
      # it's an method response and...
      getbyte(blob:res, pos:17) == 22 &&
      # response ends with 0x0b
      getbyte(blob:res, pos:len-1) == 0x0b
    ) ||
    (
      type == 2 &&
      ".Runtime.Remoting." >< res
    )
  ) security_note(port);
}
