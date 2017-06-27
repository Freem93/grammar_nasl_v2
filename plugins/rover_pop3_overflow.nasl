#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10206);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-0060");
 script_bugtraq_id(894);
 script_osvdb_id(1176);

 script_name(english: "Rover POP3 Server Username Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It might be possible to run arbitrary code on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote pop3 server seems vulnerable to a buffer overflow when 
issued a very long user name (10,000 chars)

This *may* allow an attacker to execute arbitrary commands
as root on the remote POP3 server." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor about this vulnerability and ask for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/01/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/12/27");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Attempts to overflow the pop3d buffers");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("find_service1.nasl", "qpopper.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_service(svc:"pop3", default: 110, exit_on_fail: 1);
fake = get_kb_item("pop3/"+port+"/false_pop3");
if(fake)exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

  r = recv_line(socket:soc, length:4096);
  if(!r)exit(0);
  if ( "rover" >!< tolower(r)) exit(0);
  c = string("USER ", crap(10000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(2000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if(!d)
    {
    security_hole(port);
    }
  else {
    if (service_is_dead(port: port) > 0)
      security_hole(port);
    }
  close(soc);
