#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10167);
 script_version ("$Revision: 1.41 $");
 script_cvs_date("$Date: 2017/05/05 17:46:22 $");

 script_name(english:"NTMail3 Arbitrary Mail Relay");
 script_summary(english:"Checks if the remote mail server can be used as a spam relay.");
 
 script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote SMTP server allows anyone to use
it as a mail relay provided that the source address is set to '<>'.
This issue allows any spammer to use your mail server to send their
mail to the world, thus flooding your network bandwidth and possibly
getting your mail server blacklisted.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Email_spam");
 script_set_attribute(attribute:"see_also", value:"http://www.nthelp.com/40/ntmailspam.htm");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your SMTP server so that it cannot be used as an
indiscriminate SMTP relay. Make sure that the server uses appropriate
access controls to limit the extent to which relaying is possible.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

 script_set_attribute(attribute:"vuln_publication_date", value: "1999/06/06");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "smtp_relay.nasl", "sendmail_expn.nasl", "smtp_settings.nasl");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");
include("network_func.inc");

if(islocalhost())exit(0);
if (is_private_addr()) exit(0);

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
# Don't give the information twice
if (get_kb_item("SMTP/" + port + "/spam")) exit(0);

 domain = get_kb_item("Settings/third_party_domain");
 if(!domain) domain = "nessus.org";
 
soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");
 
 data = smtp_recv_banner(socket:soc);
 if(!data)exit(0);
 if(!ereg(pattern:"^220 ", string:data))exit(0);
 
 crp = string("HELO ", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^250 ", string:data))exit(0);
 
send(socket:soc, data: 'MAIL FROM:<>\r\n');
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^250 ", string:data))exit(0);
 crp = string("RCPT TO: nobody@", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 ", string:data)){
 	send(socket:soc, data:'DATA\r\n');
	data = recv_line(socket:soc, length:1024);
	if(ereg(pattern:"^[2-3][0-9][0-9] .*", string:data))security_hole(port);
	}
 close(soc);

