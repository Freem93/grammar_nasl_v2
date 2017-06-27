#
# (C) Tenable Network Security, Inc.
#

# This plugin positively identifies notes-to-notes communication (on top
# of port 1352)



include("compat.inc");

if (description)
{
 script_id(11410);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2011/03/11 21:52:36 $");

 script_name(english:"IBM Lotus Notes Detection");

 script_set_attribute(attribute:"synopsis", value:
"A Lotus Notes or Domino server is listening on this port." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the Notes Remote Procedure Call protocol,
which is used by Lotus Notes and Lotus Domino to communicate with
other servers." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/17");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if a remote host is Domino");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_require_ports(1352);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = 1352;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = raw_string(0x3A, 0x00,
 		  0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x02, 0x00,
		  0x00, 0x40, 0x02, 0x0F, 0x00, 0x01, 0x00, 0x3D,
		  0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
		  0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00);
		  
 send(socket:soc, data:req);
 r = recv(socket:soc, length:2);
 if(!r)exit(0);
 
 len = ord(r[0]) + ord(r[1])*256;
 r = recv(socket:soc, length:len);
 close(soc);
 if("CN=" >< r)
 {
  name = "";
  r = strstr(r, "CN=");
  for(i=0;i<strlen(r);i++)
  {
   if(ord(r[i]) < 10)break;
   else name += r[i];
  }
  
  register_service(port:port, proto:"notes");

  report = string(
    "\n",
    "The name of the remote server is :\n",
    "\n",
    "  ", name
  );
  security_note(port:port, extra:report);
 }
}
