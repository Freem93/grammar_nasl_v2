#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23786);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/01/03 22:36:51 $");

  script_name(english:"Novell ZenWorks Asset Management Server Detection");
  script_summary(english:"Detects a Novell ZenWorks Asset Management Server");

  script_set_attribute(attribute:"synopsis", value:
"A management server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a collection client service from Novell
ZenWorks Asset Management Server, a software and network management
solution.");
  # http://web.archive.org/web/20061207035423/http://www.novell.com/products/zenworks/assetmanagement/overview.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd4a4e72");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 7461);

  exit(0);
}

include ("byte_func.inc");
include ("global_settings.inc");
include ("misc_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = 7461;

if (!get_tcp_port_state(port))
  exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit(0);


req = mkbyte (0x00) + crap(data:raw_string(0), length:0x0d) + mkword (0) +
	mkword (0xfe) +
	mkword (0x0) +
	mkdword (0x40000);

send(socket:soc, data:req);
res = recv (socket:soc, length:4096);

if ("TS.Census module" >< res)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"novell_zenworks_asset");
  set_kb_item(name:"Novell/AMCC", value:TRUE);
  security_note(port);
}
