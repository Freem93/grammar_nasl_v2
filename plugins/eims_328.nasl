#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20394);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-0141");
  script_bugtraq_id(16179);
  script_xref(name:"OSVDB", value:"22288");
  script_xref(name:"OSVDB", value:"55109");
  script_xref(name:"OSVDB", value:"55110");

  script_name(english:"Eudora Internet Mail Server (EIMS) < 3.2.8 Multiple DoS");
  script_summary(english:"Checks for multiple denial of service vulnerabilities in Eudora Internet Mail Server < 3.2.8");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple denial of service flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Eudora Internet Mail Server, a
mail server for Macs. 

According to its banner, the version of Eudora Internet Mail Server
(EIMS) installed on the remote host is reportedly susceptible to denial
of service attacks involving malformed NTLM authentication requests as
well as corrupted incoming MailX and temporary mail files.  While not
certain, the first issue is likely to be remotely exploitable." );
 script_set_attribute(attribute:"see_also", value:"http://www.eudora.co.nz/updates.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to EIMS version 3.2.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/09");
 script_cvs_date("$Date: 2011/02/27 00:18:37 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl");
  script_require_ports("Services/smtp", 25, 106, "Services/pop3", 110, "Services/imap", 143);

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
if (
  banner && 
  egrep(pattern:"^[0-9][0-9][0-9] .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_warning(port);
  exit(0);
}
# - IMAP.
port = get_kb_item("Services/imap");
if (!port) port = 143;
banner = get_imap_banner(port:port);
if (
  banner && 
  egrep(pattern:"^\* OK .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_warning(port);
  exit(0);
}
# - POP3.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner = get_pop3_banner(port:port);
if (
  banner && 
  egrep(pattern:"^\+OK .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_warning(port);
  exit(0);
}
# - ACAP
port = get_kb_item("Services/acap");
if (! port) port = 674;
banner = get_unknown_banner(port:port);
if (
  banner && 
  egrep(pattern:"IMPLEMENTATION Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_warning(port);
  exit(0);
}
# - POP3 password
port = get_kb_item("Services/pop3pw");
if (! port) port = 106;
banner = get_unknown_banner(port:port);
if (
  banner && 
  egrep(pattern:"^[0-9][0-9][0-9] .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_warning(port);
  exit(0);
}
