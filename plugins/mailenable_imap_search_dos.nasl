#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title (10/22/09)


include("compat.inc");

if (description)
{
  script_id(15487);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2012/04/26 00:44:35 $");

  script_cve_id("CVE-2004-2194");
  script_bugtraq_id(11418);
  script_osvdb_id(10728);

  script_name(english:"MailEnable IMAP Server SEARCH Command Remote DoS");
  script_summary(english:"Checks for Search DoS Vulnerability in MailEnable's IMAP Service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a remote denial of service
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The target is running at least one instance of MailEnable's IMAP
service.  A flaw exists in MailEnable Professional Edition versions
1.5a-d that results in this service crashing if it receives a SEARCH
command.  An authenticated user could send this command either on
purpose as a denial of service attack or unwittingly since some IMAP
clients, such as IMP and Vmail, use it as part of the normal login
process." );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/professionalhistory.asp" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional 1.5e or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/17");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2012 George A. Theall");
  script_family(english:"Windows");
  script_dependencie("find_service1.nasl", "global_settings.nasl");
  script_require_ports("Services/imap", 143);
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if ((user == "") || (pass == "")) {
  exit(1, "imap/login and/or imap/password are empty");
}

# NB: MailEnable doesn't truly identify itself in the banner so we just
#     blindly login and do a search to try to bring down the service 
#     if it looks like it's MailEnable.
port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking for Search DoS Vulnerability in MailEnable's IMAP Service on port ", port, ".");
if (!get_port_state(port)) exit(0);
banner = get_kb_item("imap/banner/" + port);
if ("IMAP4rev1 server ready at" >!< banner) exit(0);

# Read banner.
soc = open_sock_tcp(port);
if (soc) {
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");

  tag = 0;

  # Try to log in.
  ++tag;
  # nb: MailEnable supports the obsolete LOGIN SASL mechanism,
  #     which I'll use.
  c = string("a", string(tag), " AUTHENTICATE LOGIN");
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+ ") {
    s = s - "+ ";
    s = base64_decode(str:s);
    if ("User Name" >< s) {
      c = base64(str:user);
      debug_print("C: '", c, "'.");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);
      s = chomp(s);
      debug_print("S: '", s, "'.");
      if (s =~ "^\+ ") {
        s = s - "+ ";
        s = base64_decode(str:s);
      }
      if ("Password" >< s) {
        c = base64(str:pass);
        debug_print("C: '", c, "'.");
        send(socket:soc, data:string(c, "\r\n"));
      }
    }
  }
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp='';
  }

  # If successful, select the INBOX.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " SELECT INBOX");
    debug_print("C: '", c, "'.");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp='';
    }

    # If successful, search it.
    if (resp && resp =~ "OK") {
      ++tag;
      c = string("a", string(tag), " SEARCH UNDELETED");
      debug_print("C: '", c, "'.");
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        debug_print("S: '", s, "'.");
        m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp='';
      }

      # If we don't get a response, make sure the service is truly down.
      if (!resp) {
        debug_print("no response received.");
        close(soc);
        soc = open_sock_tcp(port);
        if (!soc) {
          debug_print("imap service is down.");
          security_warning(port);
          exit(0);
        }
        debug_print("imap service is up -- huh?");
      }
    }
  }

  # Logout.
  ++tag;
  c = string("a", string(tag), " LOGOUT");
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }
  close(soc);
}
