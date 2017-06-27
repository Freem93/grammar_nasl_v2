#
# (C) Tenable Network Security, Inc.
#

# Refs:
#  From: "NGSSoftware Insight Security Research" <nisr@nextgenss.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: Multiple Buffer Overflow Vulnerabilities in SLMail (#NISR07052003A)
#  Date: Wed, 7 May 2003 17:44:22 +0100

# The other issues (POP and POPPASSWD) should be covered by miscflood and pop3_overflows.nasl

include( 'compat.inc' );

if(description)
{
  script_id(11593);
  script_version ("$Revision: 1.18 $");
  script_cve_id("CVE-2003-0264");
  script_bugtraq_id(7512, 7515, 7519, 7525, 7526);
  script_osvdb_id(11973, 11974, 11975, 11976);

  script_name(english:"SLMail < 5.1.0.4433 Multiple Command Remote Overflows");
  script_summary(english:"Overflows the remote SMTP server");
 
  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to multiple buffer overflows."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running a version of the SLmail
SMTP server which is vulnerable to various overflows
which may allow to execute arbitrary commands on this
host or to disable it remotely."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to SLMail 5.1.0.4433 or newer"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Seattle Lab Mail 5.5 POP3 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:"http://marc.info/?l=bugtraq&m=105232506011335&w=2"
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!egrep(pattern:"^220 .*", string:s))
  {
   close(soc);
   exit(0);
  }

  if( safe_checks() )
  {
   if(egrep(pattern:"^220 .*SMTP Server SLmail ([0-4]\.|5\.(0\.|1\.0\.([0-9][0-9]?[0-9]?[^0-9]|([0-3]|4([0-3]|4([0-2]|3[0-2]))))))",
   	    string:s))security_hole(port);
   exit(0);
  }


  c = string("EHLO ", crap(1999), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  close(soc);

if (service_is_dead(port: port) > 0)
  security_hole(port);

