#
# (C) Tenable Network Security, Inc.
#

# References:
# From: "Michal Zalewski" <lcamtuf@echelon.pl>
# To: bugtraq@securityfocus.com
# CC: sendmail-security@sendmail.org
# Subject: RAZOR advisory: multiple Sendmail vulnerabilities

include("compat.inc");

if (description)
{
 script_id(11086);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-2001-0713");
 script_bugtraq_id(3377);
 script_osvdb_id(9301);
 
 script_name(english: "Sendmail -C Malformed Configuration Privilege Escalation");
 script_summary(english: "Checks sendmail version number for 'custom config file'");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a privilege escalation attack.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to a 'Mail System Compromise' when a user supplies a custom
configuration file. 

Although the mail server is suppose to run as a non-privileged user, a
programming error allows the local attacker to regain the extra
dropped privileges and run commands as root.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Sendmail.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();
		    
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc."); 
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:".*Sendmail.*[^/]8\.12\.0.*", string:banner))
 	security_warning(port);
