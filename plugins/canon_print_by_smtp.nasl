#
# (C) Tenable Network Security, Inc.
#

# A big thanks to Andrew Daviel
#


include("compat.inc");


if(description)
{
 script_id(14819);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0564", "CVE-2004-2166");
 script_bugtraq_id(11247);
 script_osvdb_id(132, 9346);

 script_name(english:"Canon ImageRUNNER SMTP Arbitrary Content Printing");
 script_summary(english:"Determines if the remote host is a Canon ImageRUNNER Printer");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote printer has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description", value:
"The remote host seems to be a Canon ImageRUNNER printer, which runs a
SMTP service.

It is possible to send an email to the SMTP service and have it
printed out. An attacker may use this flaw to send an endless stream
of emails to the remote device and cause a denial of service by using
all of the print paper." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Sep/322"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable the email printing service via the device's web interface."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/23");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if(!port)port = 25;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = smtp_recv_line(socket:soc);
if ( ! banner ) exit(0);

if ( !ereg(pattern:"^220 .* SMTP Ready.$", string:banner ) ) exit(0);
send(socket:soc, data:'EHLO there\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^550 Command unrecognized", string:banner) ) exit(0);
send(socket:soc, data:'HELO there\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 . Hello there \[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\] please to meet you\.", string:banner) ) exit(0);

send(socket:soc, data:'RCPT TO: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^503 need MAIL From: first\.", string:r) ) exit(0);

send(socket:soc, data:'MAIL FROM: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 nessus\.\.\. Sender Ok", string:r) ) exit(0);
send(socket:soc, data:'RCPT TO: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 nessus\.\.\. Receiver Ok", string:r) ) exit(0);

security_warning(port);
