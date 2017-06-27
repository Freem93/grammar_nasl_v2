#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26912);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2012/04/26 16:48:51 $");

  script_name(english:"CA BrightStor HSM Engine Detection (TCP)");
  script_summary(english:"Scans for HSM Engine via TCP");

 script_set_attribute(attribute:"synopsis", value:
"A data migration service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a BrightStor HSM Engine, the engine component of
BrightStor Hierarchical Storage Manager, which is used to manage files
on the remote host as part of an enterprise-grade tiered storage
solution." );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/products/product.aspx?id=1541" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/04");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 2000);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

 
if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(2000);
  if (!port) exit(0);
}
else port = 2000;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send an initial message.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = mkdword(0x42) +
  mkdword(0x07) +
  mkdword(0x00) +
  mkdword(0x00);
req = 
  mkdword(strlen(req)+4) +
  req;
send(socket:soc, data:req);


# Read the reply.
res = recv(socket:soc, length:4);
if (strlen(res) != 4) exit(0);

len = getdword(blob:res, pos:0);
# nb: the 100 character limit is arbitrary but will avoid wasting time if
#     the remote is a more verbose service.
if (len > 4 && len < 100)
{
  len -= 4;
  res = recv(socket:soc, length:len);

  # If...
  if (
    # it's the expected length and...
    strlen(res) == len &&
    # the initial dword is 0x42 and...
    0x42 == getdword(blob:res, pos:0) &&
    # the second dword is 0x07 and...
    0x07 == getdword(blob:res, pos:4)
  )
  {
    # Register and report the service.
    register_service(port:port, proto:"hsm_csagent");
    security_note(port);
  }
}
