#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(15891);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote control service is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote service is the TCP contact port for Timbuktu, a remote
control software application for Windows and Mac OS X." );
 script_set_attribute(attribute:"see_also", value:"http://netopia.com/software/products/tb2/" );
 script_set_attribute(attribute:"solution", value:
"Make sure the use of this software is done in accordance with your
corporate security policy.  If this service is unwanted or not needed,
disable it or filter incoming traffic to this port.  Otherwise make
sure to use strong passwords for authentication." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
  script_name(english:"Timbuktu Detection (TCP)");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Detect Timbuktu";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown", 407);
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
 port = get_unknown_svc(407);
 if ( ! port ) exit(0);
}
else port = 407;

if ( ! service_is_unknown(port:port) ) exit(0);
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:raw_string(0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

data = recv(socket:soc, length:6);
if ( strlen(data) == 6 && ord(data[0]) == 1 && ord(data[1]) == 1 ) 
 	{
	length = ord(data[5]);
	if (length == 0) exit(0);
	data = recv(socket:soc, length:length);
	if ( strlen(data) != length ) exit(0);
	#length = ord(data[38]);
	#if ( length + 39 >= strlen(data) ) exit(0);
	#hostname = substr(data, 39, 39 + length - 1);
	register_service(port:port, proto:"timbuktu");
 	security_note ( port );
	}
