#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10438);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2000-0490");
 script_bugtraq_id(1297);
 script_osvdb_id(340);

 script_name(english:"NetWin DSMTP (Dmail) ETRN Command Overflow");
 script_summary(english:"Checks if the remote mail server is vulnerable to a ETRN overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote SMTP server has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote SMTP server is vulnerable to a buffer overflow when the
ETRN command is issued arguments which are too long. A remote attacker
could exploit this to crash the SMTP server, or possibly execute
arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jun/15");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the SMTP server. If you are using
NetWin DSMTP, upgrade to version 2.7r or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/06/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/07");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default:25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(safe_checks())
{
 banner = get_smtp_banner(port:port);

 if(banner)
 {
  if("2.7r" >< banner)exit(0);

  if(egrep(string:banner,
  	  pattern:"^220.*DSMTP ESMTP Server v2\.([0-7]q*|8[a-h]).*"))
	  {
	 security_hole(port:port, extra:'\nNessus only checked the SMTP banner.\n');
 	}
 }
  exit(0);
}


soc = open_sock_tcp(port);
if (! soc) exit(1);

 data = smtp_recv_banner(socket:soc);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("ETRN ", crap(500), "\r\n");
 send(socket:soc, data:crp);
 send(socket:soc, data:string("QUIT\r\n"));
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port:port, extra:'\nNessus crashed the SMTP server.\n');
 else close(soc2);
