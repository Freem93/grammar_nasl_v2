#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11897);
 script_version("$Revision: 1.27 $");
 
 script_name(english:"NetInfo Daemon Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A NetInfo daemon is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"A 'NetInfo' daemon is running on this port.  NetInfo is in charge of
maintaining databases (or 'maps') regarding the system.  Such
databases include the list of users, the password file, and more.  If
the remote host is not a NetInfo server, this service should not be
reachable directly from the network." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/19");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of NetInfo");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencies("find_service1.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown", 1033);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


function netinfo_recv(socket)
{
 local_var buf, len;

 buf = recv(socket:socket, length:4);
 if(strlen(buf) < 4)return NULL;

 len = ord(buf[3]) + ord(buf[2])*256;

 buf += recv(socket:socket, length:len);
 if(strlen(buf) != len + 4)return NULL;
 return buf;
}


if (  thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
 port = get_unknown_svc(1033);
 # This service is a silent_service() 
else 
 port = 1033;

if(!port)exit(0);

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:raw_string(
		0x80, 0x00, 0x00, 0x28, 0x6e, 0xfd, 0x67, 0xa9,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 ,0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00));

r = netinfo_recv(socket:soc);
close(soc);
if(r && "6efd67a9" >< hexstr(r) && strlen(r) == 40 && ord(r[11]) == 0x01 && ord(r[0]) == 0x80 && ord(r[strlen(r) - 2]) == 0)
{
 register_service(port:port, proto:"netinfo");
 security_note(port);
}
