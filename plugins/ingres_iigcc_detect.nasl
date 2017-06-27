#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25572);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2011/07/02 19:33:54 $");

  script_name(english:"Ingres Communications Server Detection");
  script_summary(english:"Tries to connect to Ingres Communications Server");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an Ingres Communications Server, also known as a
Net Server.  This is the main process component of Ingres Net and
monitors communications between applications and DBMS servers." );
 script_set_attribute(attribute:"see_also", value:"http://docs.ingres.com/connectivity/toc" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 21064, 21065);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:21064);
}
else ports = make_list(21064);
ports = add_port_in_list(list:ports, port:21065);


user = SCRIPT_NAME;
seq = rand() & 0xff00;
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

init = mkbyte(0x22) +
  mkbyte(0xe0) +                       # TPDU type
  mkbyte(0x00) +                       # ?, appears constant
  mkbyte(0x00) +                       # initial connection id
  mkword(seq) +                        # some sort of sequence
  mkbyte(0x20) +                       # ?, appears constant
  mkbyte(0xc1) +                       # ?, appears constant
    mkbyte(0x02) +
    raw_string(0x00, 0x00) +
  mkbyte(0xc2) +                       # ?, appears constant
    mkbyte(0x02) +
    raw_string(0x00, 0x00) +
  mkbyte(0xc0) +                       # ?, appears constant
    mkbyte(0x01) +
    raw_string(0x0f) +
  mkbyte(0xc4) +                       # ?, appears constant
    mkbyte(0x01) +
    raw_string(0x02) +
  mkbyte(0xc7) +                       # ?, varies
    mkbyte(0x08) +
    raw_string(0x55, 0x3e, 0x58, 0x95, 0xb0, 0x14, 0xc2, 0xb2) +
  mkbyte(0xc5) +                       # ?, appears constant
    mkbyte(0x02) +
    raw_string(0x00, 0x02) +
  mkbyte(0xe1) +
    mkbyte(0x00) +                     # ?, appears constant
    mkbyte(0x10) + 
    mkbyte(0x00) + 
      mkbyte(0x0e) +
        "GCSO" + 
        raw_string(
          0x02, 0x06, 0x01, 0x00, 0x00, 0x04, 0x6c, 0xf0,
          0xd9, 0xe0
        );



# Loop through each port.
foreach port (ports)
{
  if (service_is_unknown(port:port) && get_tcp_port_state(port))
  {
    soc = open_sock_tcp(port);
    if (soc)
    {
      # Initiate a connection.
      send(socket:soc, data:mkword(strlen(init)+2)+init);
      res = recv(socket:soc, length:1024);

      # If...
      if (
        # the word at the first byte is the packet length and...
        strlen(res) > 12 && getword(blob:res, pos:0) == strlen(res) &&
        # the word at position 2 looks right and...
        getword(blob:res, pos:2) == 0xd01e &&
        # the word at position 4 equals our sequence and...
        getword(blob:res, pos:4) == seq &&
        # the string after the connection id looks right
        stridx(res, raw_string(0x20, 0xc1, 0x02, 0x00, 0x00)) == 8
      ) 
      {
        # Grab the connection id.
        conn_id = getbyte(blob:res, pos:7);

        # Try to log in.
        req = mkbyte(0x04) +
          mkbyte(0xf0) +                     # TPDU type
          mkbyte(0x00) +                     # ?, appears constant
          mkbyte(conn_id) +
          raw_string(0x80, 0x0d, 0x9a, 0x16, 0x01, 0x01) + 
          mkbyte(0xc1) +
            mkbyte(0x6e) + 
            raw_string(
              0x00, 0x00, 0x00, 0x00, 0x07, 0x03, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
              0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x03, 
              0x00, 0x1c, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x06, 0x06, 0x00
            ) +
            mkbyte(strlen("/iinmsvr")) + "/iinmsvr" +
            crap(data:raw_string(0x00), length:0x38) +
          mkbyte(0xc2) +
            mkbyte(0xff) + 
            raw_string(
              0x00, 0x23, 0x13, 0x02, 0x00, 0x12, 0x16, 0x02, 
              0x00, 0x3e, 0x0a
            ) +
            mkbyte(strlen(user)+1) + user + raw_string(0) +
            mkbyte(0x0b) +
              mkbyte(0x10) + 
              raw_string(
                0x09, 0xc6, 0xaa, 0x25, 0x19, 0x2f, 0xcd, 0x2a, 
                0xcf, 0xda, 0xdb, 0xa0, 0xdd, 0xc5, 0x4a, 0x88
              );
        req = mkword(strlen(req)+2) + req;
        send(socket:soc, data:req);
        res = recv(socket:soc, length:1024);

        if (
          # the word at the first byte is the packet length and...
          (strlen(res) > 4 && getword(blob:res, pos:0) == strlen(res))  &&
          # the word at position 2 looks right.
          getword(blob:res, pos:2) == 0xf004
        ) 
        {
          # Register and report the service.
          register_service(port:port, ipproto:"tcp", proto:"iigcc");
          security_note(port);
        }
      }
      close(soc);
    }
  }
}
