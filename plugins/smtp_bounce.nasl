#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10258);
  script_version ("$Revision: 1.36 $");
  script_cve_id("CVE-1999-0203");
  script_bugtraq_id(2308);
  script_osvdb_id(203);

  script_name(english:"Sendmail MAIL FROM Command Arbitrary Remote Command Execution");
  script_summary(english:"Checks if the remote mail server can be used to gain a shell");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote SMTP server is vulnerable to authentication bypass.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote SMTP server did not complain when issued the
command :

	MAIL FROM: |testing

This probably means that it is possible to send mail
that will be bounced to a program, which is
a serious threat, since this allows anyone to execute
arbitrary commands on this host.

*** This security hole might be a false positive, since
*** some MTAs will not complain to this test, but instead
*** just drop the message silently'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade your MTA or change it.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(
    attribute:'see_also',
    value:'http://securitydigest.org/phage/archive/324'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1988/12/04");
 script_cvs_date("$Date: 2016/12/09 21:04:55 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl", "smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 if(!data)exit(0);
 if("Sendmail" >!< data)exit(0);

 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("MAIL FROM: |testing\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 if(data=="250 ")security_hole(port);
 close(soc);
 }
}
