#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19607);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/29 21:03:42 $");

  script_name(english:"HP OpenView Topology Manager Daemon Detection");
  
 script_set_attribute(attribute:"synopsis", value:
"An HP OpenView Topology Manager service is listening on this port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HP OpenView Topology Manager Daemon 
for IP discovery and layout. This service is part of the HP OpenView
Management suite." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic to 
this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview");
script_end_attributes();

  script_summary(english:"Checks for HP OpenView Topology Manager Daemon");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_require_ports(2532);
  exit(0);
}

#

include("global_settings.inc");
include ("misc_func.inc");

port = 2532;
soc = open_sock_tcp (port);
if (!soc) exit (0);

req = raw_string (0x00,0x00,0x00,0x06,0x6e,0x65,0x73,0x73,0x75,0x73);

send (socket:soc, data:req);
buf = recv(socket:soc, length:16);

if ("0000000c000000020000000100000000" >< hexstr(buf))
{
  register_service (port:port, proto:"ovtopmd");
  security_note(port);
}
