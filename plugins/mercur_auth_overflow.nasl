#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11910);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2003-1177");
 script_bugtraq_id(8861, 8889);
 script_osvdb_id(2688, 55623);

 script_name(english:"MERCUR Mailserver SMTP / IMAP / POP3 Servers Remote Overflows");
 script_summary(english:"Checks for the Mercur remote buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote mail server is prone to a buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The remote Atrium MERCUR SMTP server (mail server) seems to be
vulnerable to a remote buffer overflow. Successful exploitation of
this vulnerability would give a remote attacker administrative access
to the mail server and access to potentially confidential data.

The IMAP and POP3 servers are affected by similar issues involving the
AUTHENTICATE and AUTH commands respectively.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Oct/1427" );
 script_set_attribute(attribute:"see_also", value:"http://www.atrium-software.com/mercur/mercur_e.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to MERCUR Mailserver 4.2 SP3a or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencie("smtpserver_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (!get_port_state(port)) exit(0);


if ( safe_checks() )
{
 banner = get_smtp_banner(port:port);
 if ( ! banner ) exit(0);

 if(egrep(pattern:"^220.*MERCUR SMTP-Server .v([0-3]\.|4\.0?([01]\.|2\.0))",
	  string:banner))security_hole(port);
 exit(0);
}

# this test string provided by
# Kostya KORTCHINSKY on FD mailing list at netsys

req = string("AUTH PLAIN kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ");


banner = get_smtp_banner(port:port);
if ("MERCURE SMTP-Server" >!< banner)
  exit (0);

soc=open_sock_tcp(port);
if (!soc) exit(0);
send (socket:soc, data:req);
close(soc);
soc = open_sock_tcp(port);
if (!soc) security_hole(port);
exit(0);












