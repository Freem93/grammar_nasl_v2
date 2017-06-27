#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24238);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_name(english:"ARCserve Backup for Laptops & Desktops Server Detection");
  script_summary(english:"Detects an ARCserve Backup for Laptops & Desktops Server");

  script_set_attribute(attribute:"synopsis", value:
"There is a backup service running on the remote host.");
  script_set_attribute(attribute:"description", value:
"BrightStor ARCserve Backup for Laptops & Desktops Server / BrightStor
Mobile Backup Server, an enterprise class backup solution for remote
and mobile Windows-based PCs, is installed on the remote host.  And
the service listening on this port is used by clients to backup and
restore files.");
  script_set_attribute(attribute:"see_also", value:"https://www.ca.com/us.html");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:brightstor_arcserve_backup_laptops_desktops");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 2200);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(2200);
  if (!port) exit(0);
}
else port = 2200;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Probe the service.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
magic = mkdword(0x1b2c3d4e);

req = magic + crap(data:mkbyte(0), length:256);
send(socket:soc, data:req);

res = recv(socket:soc, length:24);
if (res == NULL) exit(0);


# If ...
if (
  # the response length is 24 and...
  strlen(res) == 24 &&
  # it starts with our "magic" and ...
  stridx(res, magic) == 0 && 
  # the second dword is 0xfe
  getdword(blob:res, pos:8) == 0xFE
)
{
  # Read the next packet.
  res = recv(socket:soc, length:24);
  if (res == NULL) exit(0);
  
  if (
    # the response length is 24 and...
    strlen(res) == 24 &&
    # it starts with our "magic" and ...
    stridx(res, magic) == 0 && 
    # the second dword is 0xff
    getdword(blob:res, pos:8) == 0xFF
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"lgserver");
    security_note(port);
  }
}
