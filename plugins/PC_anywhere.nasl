#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10006);
 script_version ("$Revision: 1.31 $");
 script_cvs_date("$Date: 2013/02/14 20:12:19 $");

 script_name(english:"Symantec pcAnywhere Status Service Detection (UDP)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has pcAnywhere enabled." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Symantec pcAnywhere Status server, a service
used to discover pcAnywhere servers on a network." );
 script_set_attribute(attribute:"solution", value:
"Disable pcAnywhere if you do not use it, and do not allow this service to
run across the Internet." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/12/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks for the presence pcAnywhere Status service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");


exit(0);
}


port = 5632;
if (!get_udp_port_state(port)) exit (0);

soc = open_sock_udp(port);
if (!soc) exit(0);

send (socket:soc, data:"NQ");
buf = recv(socket:soc, length:100);

if (egrep(pattern:"^NR(.*)_+A.M.*$", string:buf))
{
 hostname = ereg_replace(pattern:"^NR([^_]+)_+A.M.*$", string:buf, replace:"\1");
 report = string(
    "\n",
    "Symantec server hostname (Netbios name): ",
    hostname, "\n"
  );

 security_note(port:port, extra:report, protocol:"udp");
}
