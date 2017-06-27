#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10885);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2013/12/23 22:44:06 $");
 script_cve_id("CVE-2002-0055");
 script_bugtraq_id(4204);

 script_name(english:"Microsoft Windows SMTP Service Malformed BDAT Request Remote DoS");
 script_summary(english:"Checks if the remote SMTP server can be restarted");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote SMTP server fail and restart by
sending specially crafted 'BDAT' requests.

The service will restart automatically, but all the connections
established at the time of the attack will be dropped.

An attacker may use this flaw to make mail delivery to your site
less efficient.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-012");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101558498401274&w=2");
 # http://web.archive.org/web/20020417221630/http://www.digitaloffense.net/mssmtp/mssmtp_dos.pl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee067e2c");
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/06");
 script_osvdb_id(732);
script_xref(name:"MSFT", value:"MS02-012");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2013 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc);
 crp = 'HELO example.com\r\n';
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!(ereg(pattern:"^250 .* Hello .*", string:data)))exit(0);


 crp = 'MAIL FROM: nessus@nessus.org\r\n';

 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = 'RCPT TO: Administrator\r\n';
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = 'BDAT 4\r\n';
 send(socket:soc, data:crp);
 crp = 'b00mAUTH LOGIN\r\n';
 send(socket:soc, data:crp);
 r = recv_line(socket:soc, length:255);
 if(ereg(pattern:"^250 .*", string:r))
 {
 r = recv_line(socket:soc, length:5);


 # Patched server say : "503 5.5.2 BDAT Expected"
 # Vulnerable servers say : "334 VXNlcm5hbWU6"
 if(ereg(pattern:"^334 .*",string:r))
 		security_warning(port);
 }
smtp_close(socket: soc);
