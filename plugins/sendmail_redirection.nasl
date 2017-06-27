#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10250);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2013/02/05 22:09:08 $");
 
 script_name(english:"Sendmail Redirection Relaying Allowed");
 script_summary(english:"Redirection check");
 
 script_set_attribute(attribute:"synopsis", value:"The remote SMTP server is vulnerable to a redirection attack.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server accepts messages addressed to recipients
of the form 'user@host1@example.com'.  A remote attacker could
leverage this to reach mail servers behind a firewall or to avoid
detection by routing mail through the affected host.");
 script_set_attribute(attribute:"solution", value:
"Consult the sendmail documentation and modify the server's
configuration file to avoid such redirections.  For example, this may
involve adding the following statement at the top of Ruleset 98, in
sendmail.cf :

  R$*@$*@$*       $#error $@ 5.7.1 $: '551 Sorry, no redirections.'");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");

 script_dependencie("find_service1.nasl", "sendmail_expn.nasl", "smtpserver_detect.nasl");
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
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

b = smtp_recv_banner(socket:soc);
if (!b) exit(0, "Failed to receive an SMTP greeting from the server listening on port "+port+".");
if ("Sendmail" >!< b) exit(0, "The server listening on port "+port+" is not Sendmail.");

trace = strcat('S : ', b);

domain = ereg_replace(
  pattern:"[^\.]*\.(.*)",
  string:get_host_name(),
  replace:"\1"
);
s = string("HELO ", domain, "\r\n");
trace = strcat(trace, 'C : ', s);
send(socket:soc, data:s);

r = recv_line(socket:soc, length:1024);
trace = strcat(trace, 'S : ', r);   

s = string("MAIL FROM: root@", get_host_name(), "\r\n"); 
trace = strcat(trace, 'C : ', s);   
send(socket:soc, data:s);

r = recv_line(socket:soc, length:1024);
trace = strcat(trace, 'S : ', r);   

s = string("RCPT TO: root@host1@", get_host_name(), "\r\n");
trace = strcat(trace, 'C : ', s);   
send(socket:soc, data:s);

r = recv_line(socket:soc, length:255);
close(soc);
trace = strcat(trace, 'S : ', r);   

if (ereg(pattern:"^250 .*", string:r))
{
  if (report_verbosity > 0)
  {
    trace = '\n  ' + str_replace(find:'\n', replace:'\n  ', string:trace);
    trace = chomp(trace);

    report = strcat(
      '\nHere is a trace of the traffic that demonstrates the issue :',
      '\n',
      trace
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The sendmail server listening on port "+port+" is not affected.");
