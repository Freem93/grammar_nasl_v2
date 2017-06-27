#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11929);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2012/10/01 23:27:14 $");
 
  script_name(english:"SAP DB / MaxDB Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A SAP DB or MaxDB database server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"SAP DB or MaxDB, an ERP software, is running on the remote
port." );
 script_set_attribute(attribute:"see_also", value:"https://www.sdn.sap.com/irj/sdn/maxdb");
  # http://web.archive.org/web/20041231045755/http://www.mysql.com/products/maxdb/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38201e65" );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:maxdb");
script_end_attributes();

 
  summary["english"] = "Detect SAP DB / MaxDB server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 7210);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(7210);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 7210;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


s = open_sock_tcp(port);
if ( ! s ) exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
db = raw_string(
  0x00, 0xc5, 0x09, 0x00, 0xc8, 0xf6, 0x08, 0x00, 
  0x00, 0xe3, 0x0a, 0x00, 0xd4, 0x00, 0x00, 0x00
);

r = 
  mkdword(0) +                         # size (to be filled in later)
  mkdword(0x5b03) +                    # ?, but constant
  mkdword(1) +                         # ?, but constant
  mkdword(0xffffffff) +
  mkdword(0x040000) +
  mkdword(0) +                         # size (to be filled in later)
  mkdword(0x3f0200) +
  mkdword(0x0904) +
  mkdword(0x4000) +
  mkdword(0x3fd0) +
  mkdword(0x4000) +
  mkdword(0x70) +
  db +
  mkbyte(7) + "I1016" + mkword(0x400) +
  mkdword(0x032a1c50) +
  mkword(0x0152) +
  mkbyte(0x09) +
  "pdbmsrv" +
  mkbyte(0x00);
r = insstr(r, mkdword(strlen(r)), 0, 3);
r = insstr(r, mkdword(strlen(r)), 20, 23);
send(socket:s, data:r);
length = recv(socket: s, length:4, min:4);
if (strlen(length) != 4)
  exit (0);

length = getdword(blob:length, pos:0) - 4;
if (length < 7 || length > 65535)
  exit (0);

r2 = recv(socket: s, length:length, min:length);
if (strlen(r2) != length)
  exit (0);

if (getdword(blob:r2, pos:0) == 0x5c03)
{
  info = "";

  # Send a "version" command.
  r = 
    mkdword(0) +                       # size (to be filled in later)
    mkdword(0x3f03) +                  # ?, but constant
    mkdword(1) +                       # ?, but constant
    mkdword(0x06cc) +
    mkdword(0x040000) +
    mkdword(0) +                         # size (to be filled in later)
    "dbm_version";
  r = insstr(r, mkdword(strlen(r)), 0, 3);
  r = insstr(r, mkdword(strlen(r)), 20, 23);
  send(socket:s, data:r);
  length = recv(socket: s, length:4, min:4);
  if (strlen(length) == 4)
  {
    length = getdword(blob:length, pos:0) - 4;
    if (length >= 7)
    {
      r2 = recv(socket: s, length:length, min:length);
      if (strlen(r2) == length && "VERSION " >< r2)
      {
        info = strstr(r2, "VERSION ");
        foreach line (split(info, sep:'\n', keep:FALSE))
        {
          items = eregmatch(pattern:"^([^ =]+) *= *(.*)$", string:line);
          if (items)
          {
            key = items[1];
            val = items[2];
            set_kb_item(name:"SAPDB/"+port+"/"+key, value:val);
          }
        }
      }
    }
  }

  if (info && report_verbosity > 0)
  {
    report = string(
      "\n",
      "Sending a 'version' command to the remote host returned :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);

  register_service(port: port, proto: "sap_db_vserver");
}
close(s);
