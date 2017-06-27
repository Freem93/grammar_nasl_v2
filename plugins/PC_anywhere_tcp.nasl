#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10794);
 script_version ("$Revision: 1.43 $");
 script_cvs_date("$Date: 2012/02/24 19:30:06 $");

 script_name(english:"Symantec pcAnywhere Detection (TCP)");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has pcAnywhere enabled." );
 script_set_attribute(attribute:"description", value:
"Symantec pcAnywhere allows a Windows user to remotely obtain a
graphical login (and therefore act as a local user on the remote
host)." );
 script_set_attribute(attribute:"solution", value:
"Disable pcAnywhere if you do not use it, and do not allow this service
to run across the Internet." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/10/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence pcAnywhere");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("os_fingerprint.nasl", "find_service1.nasl");
 script_require_ports("Services/unknown", 5631);
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");

if (thorough_tests)
{
  port = get_unknown_svc(5631);
  if (!port) exit(0);
}
else port = 5631;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

# Any script that uses this service requires a few seconds for the service to get back into the 'accepting connections' state
sleep(5);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data =  mkdword(0);

send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);

if ("005808007d080d0a002e08" >< hexstr(buf))
{
 register_service (port:port, proto:"pcanywheredata");
 security_note(port);
}
