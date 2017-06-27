#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10248);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-1999-0096");
 script_osvdb_id(196);

 script_name(english: "Sendmail decode Alias Arbitrary File Overwrite");
 script_summary(english: "Checks if the remote mail server can be used to overwrite files");
 
 script_set_attribute(attribute:"synopsis", value:"It might be possible to overwrite arbitrary files on the server.");
 script_set_attribute(attribute:"description", value:
"The remote SMTP server seems to pipe mail sent to the 'decode' alias 
to a program.

There have been in the past a lot of security problems regarding this, 
as it would allow an attacker to overwrite arbitrary files on the remote
server.

We suggest you deactivate this alias.");
 script_set_attribute(attribute:"solution", value:"Remove the 'decode' line in /etc/aliases.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1989/05/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_keys("SMTP/expn", "SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

# We need the EXPN command to be available

expn = get_kb_item("SMTP/expn");
if(!expn)exit(0);


port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);
 if (!data)
 {
  close(soc);
  exit(0);
 }
 crp = string("EXPN decode\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 .*", string:data))
 {
  if("/bin" >< data)security_warning(port);
 }
 close(soc);
 }
}
