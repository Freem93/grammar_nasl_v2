#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31717);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/05/24 20:37:09 $");

  script_name(english:"SQL Anywhere Broadcast Repeater Detection");
  script_summary(english:"Checks for a DBNS process");

 script_set_attribute(attribute:"synopsis", value:
"A database service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a SQL Anywhere Broadcast Repeater, which allows
SQL Anywhere clients to find SQL Anywhere database servers running on
other subnets and through firewalls." );
 script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/developer/mobile/sqlanywhere/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = 3968;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
if (known_service(port:port, ipproto:"udp")) exit(0);

soc = open_sock_udp(port);
if (!soc) exit(0);


# Simulate a search for another DBNS process.
req = 
  "STRMDBNSBROAD" +
  raw_string(
    0x00, 0x04, 0x00, 0x03, 0x00, 0x03, 0x03, 0x01,
    0x03, 0x05, 0x02, 0x00, 0x01, 0x07, 0x02, 0x03,
    0xE9
  );
send(socket:soc, data:req);

res = recv(socket:soc, length:0x1e);
close(soc);


# If the result looks right...
if (
  strlen(res) == 0x1e &&
  stridx(res, "STRMDBNSBRESP") == 0
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"sql_anywhere_dbns");
  security_note(port:port, proto:"udp");
}
