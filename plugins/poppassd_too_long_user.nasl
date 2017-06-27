#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17295);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-1999-1113");
 script_bugtraq_id(75);
 script_osvdb_id(7035);

 script_name(english:"Eudora Internet Mail Server for Mac OS USER Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote machine." );
 script_set_attribute(attribute:"description", value:
"The remote poppassd daemon crashes when a too long name is sent after 
the USER command.

It might be possible for a remote attacker to run arbitrary code on this
machine." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or use another one." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/04/14");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Sends a too long USER command to poppassd");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");

 script_dependencies('find_service1.nasl', 'find_service_3digits.nasl');
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports(106, "Services/pop3pw");
 exit(0);
}

include('audit.inc');
include('global_settings.inc');

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_kb_item("Services/pop3pw");
if (! port) port = 106;

if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

r = recv_line(socket:soc, length:4096);
if (r !~ '^200 ') exit (0);

send(socket: soc, data: 'USER nessus\r\n');
r = recv_line(socket: soc, length: 4096);
if (r !~ '^200 ') exit (0);

send(socket: soc, data: 'PASS '+crap(4096)+'\r\n');
line = recv_line(socket: soc, length: 4096);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if (! soc) { security_hole(port); exit(0); }

if (report_paranoia > 1 && ! line)
security_hole(port: port, extra: "
The remote poppassd daemon abruptly closes the connection when it 
receives a too long USER command.
It might be vulnerable to an exploitable buffer overflow.

Note that Nessus did not crash the service, so this might be a false
positive. However, if the poppassd service is run through inetd it is
impossible to reliably test this kind of flaw.
");
