#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# References:
# Date:  Tue, 3 Jul 2001 19:05:10 +0200 (CEST)
# From: "Andrea Barisani" <lcars@infis.univ.trieste.it>
# To: bugtraq@securityfocus.com
# Subject: poprelayd and sendmail relay authentication problem (Cobalt Raq3)
#

include("compat.inc");

if (description)
{
 script_id(11080);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2017/05/09 15:19:41 $");

 script_cve_id("CVE-2001-1075");
 script_bugtraq_id(2986);
 script_osvdb_id(1893);

 script_name(english:"poprelayd & sendmail Arbitrary Mail Relay");
 script_summary(english:"Checks if the remote mail server can be used as a spam relay.");

  script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay may be running on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote SMTP server allows relaying for
users which were identified by 'POP before SMTP'. The access control
mechanism is based on the POP server logs. However, it is possible to
poison these logs, which means that any spammer could be using your
mail server to send their emails to the world, thus flooding your
network bandwidth and possibly getting your mail server blacklisted.

Note that for some SMTP servers, such as Postfix, this plugin will
display a false positive.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Email_spam");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jul/64");
 script_set_attribute(attribute:"solution", value:
"Disable poprelayd or upgrade it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", "smtp_relay.nasl", "smtp_settings.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# can't perform this test on localhost
if(islocalhost())exit(0);

port = get_service(svc:"smtp", default:25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data = smtp_recv_banner(socket:soc);
if(!data)exit(0);

domain = get_kb_item("Settings/third_party_domain");
if(!domain) domain = "nessus.org";

hel = string("HELO ", domain, "\r\n");
send(socket:soc, data:hel);
data = recv_line(socket:soc, length:1024);
mf1 = string("MAIL FROM: <test_1@", domain, ">\r\n");
send(socket:soc, data:mf1);
data = recv_line(socket:soc, length:1024);
rc1 = string("RCPT TO: <test_2@", domain, ">\r\n");
send(socket:soc, data: rc1);
data = recv_line(socket:soc, length:1024);
if ("Relaying denied. Please check your mail first." >< data) { suspicious=1;}
else if(ereg(pattern:"^250 .*", string:data))exit(0);

q = raw_string(0x22);	# Double quote
h = this_host();
mf = string("mail from:", q, "POP login by user ", q, "admin", q,
	" at (", h, ") ", h, "@example.org\r\n");
send(socket: soc, data: mf);
data = recv_line(socket:soc, length:1024);
close(soc);
#
#sleep(10);
#
soc = open_sock_tcp(port);
if (!soc) exit(0);

data = smtp_recv_banner(socket:soc);
send(socket:soc, data:hel);
data = recv_line(socket:soc, length:1024);
send(socket:soc, data:mf1);
data = recv_line(socket:soc, length:1024);
send(socket:soc, data: rc1);
i = recv_line(socket:soc, length:4);
if (i == "250 ") security_warning(port);
close(soc);
