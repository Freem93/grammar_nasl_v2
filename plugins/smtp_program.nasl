#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10261);
  script_version ("$Revision: 1.33 $");
  script_cve_id("CVE-1999-0163");
  script_osvdb_id(203);

  script_name(english:"Sendmail mail from/rcpt to Pipe Arbitrary Command Execution");
  script_summary(english:"Checks if the remote mail server can be used to gain a shell");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote SMTP server is vulnerable to authentication bypass.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote SMTP server did not complain when issued the
command :
	MAIL FROM: root@this_host
	RCPT TO: |testing

This probably means that it is possible to send mail directly
to programs, which is a serious threat, since this allows
anyone to execute arbitrary commands on this host.

*** This security hole might be a false positive, since
*** some MTAs will not complain to this test, but instead
*** just drop the message silently.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'This plugin tests for a generic condition.
    It may be remedied by upgrading, reconfiguring, or changing your SMTP Server (MTA).'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(
    attribute:'see_also',
    value:'http://securitydigest.org/phage/archive/324'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://securitydigest.org/unix/archive/039'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1988/12/04");
 script_cvs_date("$Date: 2016/12/09 21:04:55 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:eric_allman:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");
  script_dependencie("sendmail_expn.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

 data = smtp_recv_banner(socket:soc);
 if(!data || "Sendmail" >!< data)exit(0);
crp = 'HELO example.com\r\n';
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);

n = get_host_name();
if (n =~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
 n = '['+n+']';
crp = 'MAIL FROM: root@'+n+'\r\n';

 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
crp = 'RCPT TO: |testing\r\n';
 send(socket:soc, data:crp);

 data = recv_line(socket:soc, length:4);
 if(data == "250 ")security_hole(port);
 close(soc);
