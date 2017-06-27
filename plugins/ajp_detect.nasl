#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21186);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/03/11 21:18:07 $");

  script_name(english:"AJP Connector Detection");
  script_summary(english:"Sends AJP ping / nop packets");

 script_set_attribute(attribute:"synopsis", value:
"There is an AJP connector listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an AJP (Apache JServ Protocol) connector, a
service by which a standalone web server such as Apache communicates
over TCP with a Java servlet container such as Tomcat." );
 script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/connectors-doc/" );
 script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 8007, 8009);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(8009);
  if (!port) exit(0);
}
else port = 8009;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Try to determine which version of AJP is supported.
proto = NULL;

# - check for AJP13 by sending a Forward request and reading the response.
is_ssl = 0;
protocol = "HTTP/1.0";
raddr = "127.0.0.1";
req_hdrs = make_array(
  mkword(0xa00e), "Nessus", 
  mkword(0xa006), "Close"
);
srv_host = "localhost";
srv_port = "80";
uri = string("/", SCRIPT_NAME);

hdrs_str = "";
foreach key (keys(req_hdrs))
{
  val = req_hdrs[key];
  hdrs_str += key + mkword(strlen(val)) + val + mkbyte(0);
}
forward = 
  mkbyte(2) +                           # forward request
  mkbyte(2) +                           # method, 2 => GET
  mkword(strlen(protocol)) +            # protocol
    protocol + 
    mkbyte(0) +
  mkword(strlen(uri)) +                 # URI
    uri +
    mkbyte(0) +
  mkword(strlen(raddr)) +               # Remote IP
    raddr +
    mkbyte(0) +
  mkword(0xffff) +                      # Remote host
  mkword(strlen(srv_host)) +            # Server host
    srv_host +
    mkbyte(0) +
  mkword(srv_port) +                    # Server port
  mkbyte(is_ssl) +                      # Is SSL
  mkword(max_index(keys(req_hdrs))) +   # Number of request headers
    hdrs_str +
  mkbyte(0xff);
forward = 
  mkbyte(0x12) + mkbyte(0x34) +         # magic, web server -> container
  mkword(strlen(forward)) +             # length
  forward;

send(socket:soc, data:forward);

done = FALSE;
while (!done)
{
  res_1 = recv(socket:soc, length:4);
  if (
    strlen(res_1) == 4 &&
    getword(blob:res_1, pos:0) == 0x4142 &&
    getword(blob:res_1, pos:2) > 0
  )
  {
    len = getword(blob:res_1, pos:2);
    res_2 = recv(socket:soc, length:len);
    if (strlen(res_2) == len)
    {
      prefix_code = getbyte(blob:res_2, pos:0);
      if (prefix_code == 5 && len == 2)
      {
        proto = "ajp13";
        done = TRUE;
      }
      else if (prefix_code == 3 || prefix_code == 4 || prefix_code == 6) 
      {
        # do nothing
      }
      else 
      {
        # Something's wrong!
        done = TRUE;
      }
    }
    else done = TRUE;
  }
  else done = TRUE;
}
close(soc);

# - check for AJP12.
if (isnull(proto))
{
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  ping = mkword(0xfe00);
  send(socket:soc, data:ping);
  res = recv(socket:soc, length:32);
  close(soc);

  # If it looks like a valid reply...
  if (res && res == mkbyte(0))
  {
    # Try a additional set of tests since the reply 
    # isn't necesssarily uncommon.
    soc = open_sock_tcp(port);
    if (!soc) exit(0);

    # Send a NOP packet; we shouldn't get a response.
    nop = mkbyte(0);
    send(socket:soc, data:nop);
    res = recv(socket:soc, length:32);
    if (strlen(res)) exit(0);

    # Send a Ping; we should get a valid response.
    send(socket:soc, data:ping);
    res = recv(socket:soc, length:32);
    close(soc);

    # It's AJP12 if it looks like a valid response.
    if (res && res == mkbyte(0)) proto = "ajp12";
  }
}


# Register and report the service if detection was successful.
if (!isnull(proto))
{
  register_service(port:port, ipproto:"tcp", proto:proto);

  report = string(
    "\n",
    "The connector listing on this port supports the ", proto, " protocol.\n"
  );
  security_note(port:port, extra:report);
}
