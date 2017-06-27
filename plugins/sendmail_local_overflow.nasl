#
# (C) Tenable Network Security, Inc.
#

# References
# [also vulnerable to a heap overflow]
# Date:  Mon, 28 May 2001 18:16:57 -0400 (EDT)
# From: "Michal Zalewski" <lcamtuf@bos.bindview.com>
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: Unsafe Signal Handling in Sendmail
#

include("compat.inc");

if (description)
{
 script_id(10729);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-2001-0653");
 script_bugtraq_id(3163);
 script_osvdb_id(605);

 script_name(english:"Sendmail < 8.11.6 -d category Value Local Overflow");
 script_summary(english:"Check sendmail version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a privilege escalation attack.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to a local buffer overflow allowing local users to gain
root privileges.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.12beta19 or 8.11.6.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/08/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2012 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:".*sendmail.*8\.((11\.[0-5])|12.*beta([0-9][^0-9]|1[0-8]))/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
