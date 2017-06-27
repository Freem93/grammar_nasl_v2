#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25118);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-1578");
  script_bugtraq_id(23058);
  script_osvdb_id(33545);
  script_xref(name:"EDB-ID", value:"3527");

  script_name(english:"MERCUR Messaging IMAP Server NTLM Authentication NTLMSSP Argument Remote Overflow");
  script_summary(english:"Tries to crash MERCUR's IMAP Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MERCUR Messaging, a commercial mail server
for Windows. 

The IMAP server component of MERCUR Messaging is affected by a buffer
overflow vulnerability involving its support for NTLM authentication. 
An unauthenticated, remote attacker can leverage this issue to crash
the IMAP service or execute arbitrary code remotely. 

Note that MERCUR Messaging's IMAP server runs as a service with LOCAL
SYSTEM privileges by default." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/20");
 script_cvs_date("$Date: 2016/05/20 14:12:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl");
  if (NASL_LEVEL >= 3000 )
    script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, 32000);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Do banner checks of various ports. 
#
# - SMTP.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
banner = get_smtp_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR SMTP Server (v5.00.19".
  if (egrep(pattern:"^[0-9][0-9][0-9] .* MERCUR SMTP Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-9]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - POP3.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner = get_pop3_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR POP3-Server (v5.00.12".
  if (egrep(pattern:"^(\+OK|-ERR) MERCUR POP3-Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-2]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - IMAP.
port = get_kb_item("Services/imap");
if (!port) port = 143;
banner = get_imap_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR IMAP4-Server (v5.00.14".
  if (egrep(pattern:"^\* (OK|BAD|NO) MERCUR IMAP4-Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-4]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - MERCUR Control Service
port = 32000;
banner = get_unknown_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR Control-Service (v5.00.14".
  if (egrep(pattern:"^MERCUR Control-Service \(v([0-4]\.|5\.00\.(0[0-9]|1[0-4]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
