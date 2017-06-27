#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10047);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-1999-1521");
 script_bugtraq_id(633);
 script_osvdb_id(40);

 script_name(english:"CMail MAIL FROM Command Remote Overflow");
 script_summary(english:"Overflows a buffer in the remote mail server");

 script_set_attribute(attribute:"synopsis", value:"The remote mail server has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a vulnerable version of CMail.
Issuing a long argument to the 'MAIL FROM' command can result in a
buffer overflow. An attack would look something similar to :

 MAIL FROM: AAA[...]AAA@nessus.org

Where AAA[...]AAA contains more than 8000 'A's.

A remote attacker could exploit this issue to crash the mail server,
or possibly to execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Oct/297");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=93720402717560&w=2");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for a fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/05/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/29");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "tfs_smtp_overflow.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken'))
  exit(1, "MTA on port "+port+" is broken.");

if(safe_checks())
{
 banner = get_smtp_banner(port:port);

  if(banner)
  {
  if(egrep(pattern:"CMail Server Version: 2\.[0-4]",
  	  string:banner))
	  {
	   alrt  =
"Nessus reports this vulnerability using only information that was
gathered. Use caution when testing without safe checks enabled.";

	  security_hole(port:port, extra:alrt);
	  }
  }
  exit(0);
 }



 key = get_kb_item(string("SMTP/", port, "/mail_from_overflow"));
 if(key)exit(0);
 soc = open_sock_tcp(port);
if (! soc) exit(1);

 data = smtp_recv_banner(socket:soc);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: ", crap(8000), "@", get_host_name(), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 if(!buf){
  close(soc);
  soc = open_sock_tcp(port);
  if(soc) s = smtp_recv_banner(socket:soc);
  else s = NULL;

  if(!s) security_hole(port);
  }
 }
 close(soc);
