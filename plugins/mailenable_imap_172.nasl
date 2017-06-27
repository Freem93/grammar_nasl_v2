#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20837);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2011/10/06 01:16:36 $");

  script_cve_id("CVE-2006-0503");
  script_bugtraq_id(16457);
  script_osvdb_id(22852);

  script_name(english:"MailEnable IMAP Server EXAMINE Command Remote DoS");
  script_summary(english:"Checks for EXAMINE command denial of service vulnerability in MailEnable IMAP server");

  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is susceptible to denial of service attacks." );
  script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

According to the version number in its banner, the IMAP server bundled
with the installation of MailEnable Professional on the remote host
may crash when handling certain EXAMINE commands.  An authenticated
attacker may be able to leverage this issue to deny service to users
with a specially crafted EXAMINE command." );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/professionalhistory.asp" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional 1.72 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/02");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "imap4_banner.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_ports("Services/smtp", 25, "Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("smtp_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# Make sure the banner is for MailEnable.
banner = get_imap_banner(port:port);
if (!banner || "* OK IMAP4rev1 server ready" >!< banner) exit(0);


# Check the version number from the SMTP server's banner.
smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

banner = get_smtp_banner(port:smtp_port);
if (
  banner && 
  banner =~ "Mail(Enable| Enable SMTP) Service"
) {
  # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
  #     Professional Edition formats it like "0-1.2-" (for 1.2), and
  #     Enterprise Edition formats it like "0--1.1" (for 1.1).
  ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
  if (!isnull(ver)) {
    if (ver[1] == NULL) edition = "Standard";
    else if (ver[1] == "0-") edition = "Professional";
    else if (ver[1] == "0--") edition = "Enterprise";
  }
  if (isnull(ver) || isnull(edition)) {
    exit(1, "cannot determine edition of MailEnable's SMTP connector service");
  }
  ver = ver[2];

  # nb: Professional versions < 1.72 are vulnerable.
  if (edition == "Professional" && ver =~ "^1\.([0-6]|7$|7[01])") {
    security_warning(port);
  }
}
