#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11733);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/05/03 18:30:33 $");

 script_name(english:"Bugbear.B Worm Detection");
 script_summary(english:"Detect Bugbear.B Worm Detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host may have been compromised.");
 script_set_attribute(attribute:"description", value:
"The BugBear.B backdoor appears to be listening on this port.  An
attacker may connect to it to retrieve secret information such as
passwords, credit card numbers, etc. 

The BugBear.B worm includes a keylogger and can kill antivirus and
firewall software.  It propagates through email and open Windows
shares.");
 script_set_attribute(attribute:"solution", value:
"- Use an antivirus package to remove it.
- Close your Windows shares
- See http://www.symantec.com/avcenter/venc/data/w32.bugbear.b@mm.removal.tool.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_dependencies("find_service2.nasl");
 script_require_ports(1080);
 exit(0);
}

#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


#
# bugbear.b is bound to port 1080. It sends data which seems to
# be host-specific when it receives the letter "p"
#
port = 1080;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (known_service(port:port)) exit(0, "The service listening on port "+port+" is known.");


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
send(socket:soc, data:"p");
r = recv(socket: soc, length: 308);
close(soc);
if (!strlen(r)) exit(0, "The service listening on port "+port+" did not respond when sent a 'p'.");


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
send(socket: soc, data: "x");
r2 = recv(socket: soc, length: 308);
if (strlen(r2)) exit(0, "The service listening on port "+port+" did respond when sent an 'x'.");
close(soc);


if (strlen(r) > 10)
{
 security_hole(port);
 register_service(port: port, proto: "bugbear_b");
 exit(0);
}
else exit(0, "The service listening on port "+port+" does not appear to be Bugbear.B.");
