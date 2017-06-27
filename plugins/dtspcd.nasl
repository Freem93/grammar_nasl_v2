#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10833);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2011/03/11 21:52:32 $");
 script_name(english:"CDE Subprocess Control Service (dtspcd) Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"dtspcd is running on this host." );
 script_set_attribute(attribute:"description", value:
"The 'dtspcd' service is running.  This service deals with the CDE
interface for the X11 system. " );
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/12/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines if dtspcd is running");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports(6112);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = 6112;

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
 pkt = raw_string(0x30, 0x30, 0x30, 0x30,
		  0x30, 0x30, 0x30, 0x32,
		  0x30, 0x34, 0x30, 0x30,
		  0x30, 0x64, 0x30, 0x30,
		  0x30, 0x31, 0x20, 0x20,
		  0x34, 0x20, 0x00, 0x72,
		  0x6F, 0x6F, 0x74, 0x00,
		  0x00, 0x31, 0x30, 0x00, 0x00);

 send(socket:soc, data:pkt);
 r = recv(socket:soc, length:4096);
  if("SPC_" >< r)
  {
   security_note(port);
  register_service(port:port, proto:"dtspcd");
  }
  close(soc);
}

