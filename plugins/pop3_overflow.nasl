#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      This one script can and does test for numerous BugIDs and CVEs.  Added reference
#           links to all posted vulnerabilities with boundary lengths less than
#           the currrent script value of 2048.
#           All of these posted in the Bugtraq Database appear vulnerable (not tested).
#           Links are current up to 11/16/2002
#

include("compat.inc");

if (description)
{
 script_id(10184);
 script_version("$Revision: 1.53 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id("CVE-1999-0822", "CVE-2000-0091", "CVE-2001-0776", "CVE-2001-1046", "CVE-2002-0454", "CVE-2002-0799", "CVE-2002-1781");
 script_bugtraq_id(2781, 2811, 4055, 4295, 4789, 790, 830, 942);
 script_osvdb_id(776, 1204, 5290, 6992, 12076, 13970, 57175, 59759);

 script_name(english:"Multiple Vendor POP3 Remote Overflows");
 script_summary(english:"Attempts to overflow the in.pop3d buffers");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote POP3 server might be vulnerable to a buffer overflow bug
when it is issued at least one of these commands, with a too long
argument :

 AUTH USER PASS

If confirmed, this problem might allow an attacker to execute
arbitrary code on the remote system.");
 script_set_attribute(attribute:"solution", value:
"If you do not use POP3, disable this service. Otherwise, upgrade to a
newer version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/27197");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service1.nasl", "qpopper.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/pop3", 110);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

to = get_read_timeout();

port = get_service(svc: "pop3", default: 110, exit_on_fail: 1);
fake = get_kb_item("pop3/"+port+"/false_pop3");
if(fake)exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

  d = recv_line(socket:soc, length:1024);
  if (!d || d !~ '^\\+OK') { close(soc); exit(0); }	# Not a POP3 server
  if ( egrep(pattern:"Qpopper.*4", string:d) ) exit(0);

  c = strcat('AUTH ', crap(2048), '\r\n');
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024, timeout: 3*to);
  if(!d)security_hole(port);
  else {
	if ( "-ERR Input buffer full, aborting" >< d ) exit(0, "Dovecot - not vulnerable");
  	c = strcat('USER ', crap(1024), '\r\n');
	send(socket:soc, data:c);
	d = recv_line(socket:soc, length:1024, timeout: 3*to);
	if(!d)security_hole(port);
	else
	{
	 if ( "-ERR Input buffer full, aborting" >< d ) exit(0, "Dovecot - not vulnerable");
	 c = strcat('PASS ', crap(1024), '\r\n');
	 send(socket:soc, data:c);
	 d = recv_line(socket:soc, length:1024, timeout: 3*to);
	 if(!d)security_hole(port);
	}
       }
   close(soc);

