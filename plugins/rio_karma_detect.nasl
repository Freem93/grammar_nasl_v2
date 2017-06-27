#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16462);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");
 
  script_name(english:"Rio Karma MP3 Player File Upload Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A hardware device which may not be approved by your corporate security
policy is plugged into the network." );
 script_set_attribute(attribute:"description", value:
"The remote device seems to be a Rio Karma MP3 player, running the Rio Kama
file upload service.

Make sure the use of such network devices are done in accordance with your 
corporate security policy." );
 script_set_attribute(attribute:"solution", value:
"If this device is not needed, disable it or filter incoming traffic
to this IP address." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Detects a Rio Karma MP3 Player");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service1.nasl");
  script_require_ports(8302);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if ( get_port_state(8302) == 0 ) exit(0);
soc = open_sock_tcp(8302);
if ( ! soc ) exit(0);

send(socket:soc, data:raw_string(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08));
r = recv(socket:soc, length:8);
if ( hexstr(r) == "5269c58d01000000" )
{
 register_service(port:8302, proto:"rio-karma-upload");
 security_note(8302);
}
