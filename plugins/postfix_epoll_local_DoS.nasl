#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34347);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_cve_id("CVE-2008-3889");
 script_bugtraq_id(30977);
 script_osvdb_id(48108);

 script_name(english:"Postfix epoll File Descriptor Leak Local DoS");
 script_summary(english:"Checks the version of the remote Postfix daemon");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to a local denial of service
attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Postfix running on the remote
host leaks 'epoll' file descriptors when it executes non-Postfix
commands from, say, a user's .forward file. A local attacker can
access the leaked epoll descriptor to launch a denial of service
attack against Postfix.

Note that this issue only affects hosts running Linux with a 2.6
kernel.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495894/100/0/threaded");
 script_set_attribute(attribute:"solution", value:"Upgrade to Postfix 2.4.9 / 2.5.5 / 2.6-20080902 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/06");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postfix:postfix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

 script_family(english:"SMTP problems");

 script_dependencie("smtpscan.nasl", "smtpserver_detect.nasl", "os_fingerprint.nasl");
 script_require_keys("Host/OS", "Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25, 587);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item("Host/OS");
if ("Linux Kernel 2.6" >!< os) exit(0);

port = get_kb_item("Services/smtp");
if (!port) port = 25;

banner = get_smtp_banner(port: port);
if (! banner) exit(0);

# Some banners look like: Postfix ... on Linux 2.4.20
# So we have to be strict
if (egrep(string: banner, pattern: " ESMTP Postfix +\(?(2\.4\.[0-8]|2\.5\.[^0-4]|2\.6-2008(0[0-8]|0901))[^0-9]"))
  security_note(port);
