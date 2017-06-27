#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28290);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");

  script_name(english:"OpenBase Detection");
  script_summary(english:"Queries OpenBase for a list of databases");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is used by OpenBase, a multi-platform relational
database server originally developed for the OpenStep platform." );
 script_set_attribute(attribute:"see_also", value:"http://www.openbase.com/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 20221, 20222);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(20221);
  if (!port) exit(0);
}
else port = 20221;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Synchronize version.
comm_ver = "2.0";

req = "#" + mkbyte(strlen(comm_ver)) + comm_ver;
send(socket:soc, data:req);
res = recv(socket:soc, length:2, min:1);


# If successful...
if (strlen(res) == 1 && getbyte(blob:res, pos:0) == 1)
{
  # Ask for a list of databases.
  req = 
    mkdword(0x06) + "|dict|" +
    mkdword(0x06) + "action" +
    mkdword(0x14) + "databaseListForHost7" +
    mkdword(-1);
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024, min:14);
  close(soc);

  # If..
  if (
    # the response is long-enough and...
    strlen(res) >= 14 &&
    # the initial dword is 6 and...
    getdword(blob:res, pos:0) == 6 &&
    # the final dword is -1 and...
    mkdword(0xffffffff) == substr(res, strlen(res)-4) &&
    # either...
    (
      # we see "|data|" at offset 4 along with our action or...
      ("|data|" == substr(res, 4, 9) && "databaseListForHost7" >< res) ||
      # we see "|dict|" at offset 4 and nothing else.
      ("|dict|" == substr(res, 4, 9) && 14 == strlen(res))
    )
  )
  {
    info = "";
    if ("|data|" == substr(res, 4, 9))
    {
      service = "openbase_admin";

      # Extract list of databases for the report.
      i = stridx(res, "databaseName = ");
      l = strlen(res);

      while (i != -1 && i+16 < l)
      {
        i += 15;
        j = stridx(res, ";", i);
        if (j == -1) i = -1;
        else 
        {
          dbname = substr(res, i, j-1);
          if (dbname !~ ' \t\r\n(){};,=') info += '  ' + dbname + '\n';
          i = stridx(res, "databaseName = ", j);
        }
      }

    }
    else service = "openbase";

    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:service);

    if (info)
      report = string(
        "The following databases are known to the remote OpenBase server :\n",
        "\n",
        info
      );
    else report = NULL;

    security_note(port:port, extra:report);
  }
}
