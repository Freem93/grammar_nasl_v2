#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if(description)
{
  script_id(18039);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");
  script_name(english:"Hydrogen Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote control service is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Hydrogen, a backdoor used by penetration
testers to gather screen shots, download files or gain control of the
remote host.

Make sure that the use of this software on the remote host is done in 
accordance with your security policy." );
 script_set_attribute(attribute:"see_also", value:"http://www.immunitysec.com/products-hydrogen.shtml" );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Detect Hydrogen";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");



  exit(0);
}

#
include ("misc_func.inc");
include ('global_settings.inc');

if ( ! thorough_tests || get_kb_item("global_settings/disable_service_discovery")  ) exit(0);

port = get_unknown_svc();
if (! port) exit(0);
if (! service_is_unknown(port:port) ) exit(0);
if (! get_port_state(port)) exit(0);

init_match = raw_string(1);
body_match = raw_string(0,0,1,0x10,0,0,0,0x1E,0,0,0,0,0,0);
req = raw_string(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
r = recv(socket:soc, length:1024);
if (r && r == init_match)
 {
       send(socket:soc, data:req);
       r = recv(socket:soc, length:14);
       if (r == body_match) security_note(port);
 }
close (soc);
