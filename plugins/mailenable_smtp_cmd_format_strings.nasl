#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17364);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_cve_id("CVE-2005-0804");
  script_bugtraq_id(12833);
  script_osvdb_id(14858);

  script_name(english:"MailEnable Standard SMTP mailto: Request Format String");
  script_summary(english:"Checks for SMTP command format string vulnerability in MailEnable SE");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is afflicted by a format string vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MailEnable Standard Edition
that suffers from a format string vulnerability in its handling of
SMTP commands.  Specifically, a remote attacker can crash the SMTP
daemon by sending a command with a format specifier as an argument. 
Due to the nature of the flaw, it is likely that an attacker can also
be able to gain control of program execution and inject arbitrary
code." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393566" );
  script_set_attribute(attribute:"solution", value:
"Apply the SMTP fix from 18th March 2005 located at
http://www.mailenable.com/hotfix/" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Make sure the banner corresponds to MailEnable.
banner = get_smtp_banner(port:port);
if (!banner || !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)) exit(0);


# If safe checks are enabled, check the version in the banner.
if (safe_checks()) {
  # nb: Standard Edition seems to format version as "1.71--" (for 1.71)
  #     while Professional Edition formats it like "0-1.2-" (for 1.2).
  ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:banner);
  if (ver == NULL) {
    exit(1, "cannot determine version of MailEnable's SMTP connector service");
  }
  if (ver[1] == NULL) {
    edition = "Standard";
  }
  else if (ver[1] == "0-") {
    edition = "Professional";
  }
  if (isnull(edition)) {
    exit(1, "cannot determine edition of MailEnable's SMTP connector service");
  }
  ver = ver[2];

  # nb: see <http://www.mailenable.com/standardhistory.asp> for history.
  if (edition == "Standard" && ver =~ "^1\.([0-7].*|8$)")
    security_warning(port);
}
# Else we'll try to crash the daemon.
else {
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # nb: it doesn't seem to matter what the actual "command" is.
  c = string("mailto: %s%s%s\r\n");
  send(socket:soc, data:c);
  repeat {
    s = recv_line(socket:soc, length:32768);
  }
  until (s !~ '^[0-9][0-9][0-9]-');
  if (!s) {
    close(soc);
    # Is the daemon history?
    if (service_is_dead(port: port) > 0)
    {
      security_warning(port);
      exit(0);
    }
  }
  smtp_close(socket: soc);
}
