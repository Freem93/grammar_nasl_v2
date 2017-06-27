#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11499);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2014/05/02 03:09:37 $");

 script_cve_id("CVE-2003-0161");
 script_bugtraq_id(7230);
 script_osvdb_id(8294);
 script_xref(name:"RHSA", value:"2003:120-01");

 script_name(english: "Sendmail < 8.12.9 NOCHAR Control Value prescan Overflow");
 
 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number,
may be vulnerable to a remote buffer overflow allowing remote
users to gain root privileges.

Sendmail versions from 5.79 to 8.12.8 are vulnerable.

NOTE: manual patches do not change the version numbers.
Vendors who have released patched versions of sendmail may still 
falsely show vulnerability.

*** Nessus reports this vulnerability using only the banner of the
*** remote SMTP server. Therefore, this might be a false positive.");
 script_set_attribute(attribute: "solution", value:
"Upgrade to Sendmail ver 8.12.9 or greater or
if you cannot upgrade, apply patches for 8.10-12 here:

http://web.archive.org/web/20031202022838/http://www.sendmail.org/patchps.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_summary(english: "Checks sendmail version number");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 
 script_family(english: "SMTP problems");
 if ( ! defined_func("bn_random") )
	script_dependencie("smtpserver_detect.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("smtpserver_detect.nasl", "os_fingerprint.nasl", "solaris7_107684.nasl", "solaris7_x86_107685.nasl", "solaris8_110615.nasl", "solaris8_x86_110616.nasl", "solaris9_113575.nasl", "solaris9_x86_114137.nasl");

 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("smtp_func.inc");

if ( get_kb_item("BID-8641") ) exit(0);


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);

banner = get_smtp_banner(port:port);
if(banner)
{
 if(egrep(pattern:"Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(/|UCB| )([5-7]\.|[^/]8\.([0-9](\.|;|$)|1[01]\.|12\.[0-8](\/| |\.|\+)))).*", string:banner, icase:TRUE))
    security_hole(port);
 else if(egrep(pattern:"Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.1[01]\..*|8\.12\.[0-8]|SMI-[0-8]\.([0-9]|1[0-2]))/.*",
  string:banner, icase:TRUE))
    security_hole(port);
}
