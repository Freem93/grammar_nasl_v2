#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10021);
 script_version ("$Revision: 1.32 $");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
 script_name(english:"Identd Service Detection");
 script_summary(english:"Checks if identd is installed");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an identification service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an ident (also known as 'auth') daemon.

The 'ident' service provides sensitive information to potential 
attackers. It is designed to say which accounts are running which 
services. This helps attackers to focus on valuable services (those
owned by root or other privileged accounts). If you do not use this 
service, and software you run does not require it, disable it." );
 script_set_attribute(attribute:"solution", value:
"If you do not use this service and software you run does not require
it, disable it." );
script_set_attribute(attribute:"risk_factor",value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/auth", 113);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("Services/auth");
if(!port)port = 113;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = string("0,0\r\n");
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  seek = "ERROR";
  if(seek >< buf)
  {
   security_note(port);
   register_service(port:port, proto:"auth");
  }
  close(soc);
 }
}

