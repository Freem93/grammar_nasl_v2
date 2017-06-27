#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31409);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"Versant Connection Services Daemon Detection");
  script_summary(english:"Emulates an 'oscp -i @$remote_host' command");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a Versant connection services daemon, a
component of the Versant Object Database software responsible for
managing connections to the database." );
 script_set_attribute(attribute:"see_also", value:"http://www.versant.com/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/10");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5019);

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
  port = get_unknown_svc(5019);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 5019;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Initiate a connection.
#
# nb: see Luigi Auriemma's versantcmd.c for some info about the 
#     protocol: http://aluigi.org/poc/versantcmd.zip
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

dbname = "o_dblist";
user = "Administrator";
versant_rel = "";
versant_root = "";
versant_db = "";
versant_dbid = "";
versant_dbid_node = "";
versant_service_name = "";
versant_command = "-utility";

req = 
  mkword(1) +
  mkword(0) +
  mkdword(0) +
  mkword(2) +
  mkword(2) +
  mkdword(1) +
  mkword(0) +
  mkword(0) +
  mkdword(0) +
  crap(data:mkbyte(0), length:8) +
  mkword(1) +
  mkword(0) +
  dbname + mkbyte(0) +
  user + mkbyte(0) +
  versant_rel + mkbyte(0);
if (strlen(req) % 4) req += crap(data:mkbyte(0), length:4-strlen(req)%4);
req += 
  mkdword(11) +
  mkdword(0x100) + 
  mkword(0) +
  mkword(0) +
  mkword(0) +
  mkbyte(0) +
  mkbyte(0) +
  get_host_name() + mkbyte(0) +
  versant_root + mkbyte(0) +
  versant_db + mkbyte(0) +
  versant_dbid + mkbyte(0) +
  versant_dbid_node + mkbyte(0) +
  crap(data:mkbyte(0), length:5) +
  versant_service_name + mkbyte(0) +
  versant_command + mkbyte(0);
req += crap(data:mkbyte(0), length:0x800-strlen(req));
send(socket:soc, data:req);

res = recv(socket:soc, length:0x800);
if (strlen(res) != 0x800) exit(0);


# If the response looks correct.
if (
  getword(blob:res, pos:8) == 1 &&
  getword(blob:res, pos:10) == 1 &&
  dbname >< res &&
  versant_command >< res
)
{
  # Read the rest of the response to get the client port, if possible.
  obe_port = 0;
  rc = getdword(blob:res, pos:4);
  if (rc == 0)
  {
    res_2 = recv(socket:soc, length:0x100, min:6);
    if (strlen(res_2))
    {
      obe_port = getword(blob:res_2, pos:4);
      res += res_2;
    }
  }

  # Try to get info about the remote version / environment.
  info = "";

  if (obe_port)
  {
    soc2 = open_sock_tcp(obe_port);
    if (soc2)
    {
      versant_command = "-noprint -i";

      req2 = 
        mkword(0x1002) +
        mkword(0x5d) +
        mkdword(0) +
        mkword(1) +
        mkword(0) +
        mkdword(0x12) +
        crap(data:mkbyte(0), length:12) +
        versant_command + mkbyte(0);
      req2 += crap(data:mkbyte(0), length:0x100-strlen(req2));
      send(socket:soc2, data:req2);

      res2 = recv(socket:soc2, length:0x100);
      if (
        strlen(res2) == 0x100 &&
        versant_command >< res2
      )
      {
        res2_2 = recv(socket:soc2, length:0x800);
        res2 += res2_2;

        ver = res2_2;
        ver = ver - strstr(ver, mkbyte(0));
        if (ver =~ "^[0-9]+\.")
        {
          set_kb_item(name:"Versant/"+port+"/Ver", value:ver);
          info += '  Product version : ' + ver + '\n';
        }

        root_path = substr(res2_2, 0x0c, 0x10b);
        root_path = root_path - strstr(root_path, mkbyte(0));
        if (root_path =~ "^([A-Za-z]:)?[\\/.]")
        {
          set_kb_item(name:"Versant/"+port+"/VERSANT_ROOT", value:root_path);
          info += '  Root Path       : ' + root_path + '\n';
        }

        db_path = substr(res2_2, 0x10c, 0x20b);
        db_path = db_path - strstr(db_path, mkbyte(0));
        if (db_path =~ "^([A-Za-z]:)?[\\/.]")
        {
          set_kb_item(name:"Versant/"+port+"/VERSANT_DB", value:db_path);
          info += '  DB Directory    : ' + db_path + '\n';
        }

        node_name = substr(res2_2, 0x30c, 0x40b);
        node_name = node_name - strstr(node_name, mkbyte(0));
        if (node_name =~ "^[A-Za-z0-9]")
        {
          set_kb_item(name:"Versant/"+port+"/VERSANT_DBID_NODE", value:node_name);
          info += '  DBID Node Name  : ' + node_name + '\n';
        }
      }
      close(soc2);
    }
  }

  # Register and report the service.
  register_service(port:port, proto:"versant_oscssd");

  if (info && report_verbosity)
  {
    report = string(
      "\n",
      info
    );
    security_note(port:port, extra:report);
  } else security_note(port);

}
close(soc);
