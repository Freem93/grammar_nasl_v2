#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB refs, output formatting, remove unrelated VDB refs, remove invalid see also link (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)

include("compat.inc");

if (description)
{
 script_id(11316);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2017/04/27 13:33:46 $");

 script_cve_id("CVE-2002-1337");
 script_bugtraq_id(6991);
 script_osvdb_id(4502);
 script_xref(name:"CERT-CC", value:"CA-2003-07");
 script_xref(name:"CERT", value:"398025");
 
 script_name(english:"Sendmail headers.c crackaddr Function Address Field Handling Remote Overflow");
 script_summary(english:"Checks the version number"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
affected by a remote buffer overflow allowing remote users to gain
root privileges. 

Sendmail versions from 5.79 to 8.12.7 are affected.

*** Nessus reports this vulnerability using only
*** the banner of the remote SMTP server. Therefore,
*** this might be a false positive.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail ver 8.12.8 or later.  If you cannot upgrade, apply
patches for 8.10-12 here :

http://www.sendmail.org/patchcr.html

NOTE: manual patches do not change the version numbers.
Vendors who have released patched versions of sendmail
may still falsely show vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 SECNAP Network Security");
  script_family(english:"SMTP problems");

 if ( ! defined_func("bn_random") ) 
 	script_dependencie("smtpserver_detect.nasl");
 else
 	script_dependencie("smtpserver_detect.nasl", "solaris26_105395.nasl", "solaris26_x86_105396.nasl", "solaris7_107684.nasl", "solaris7_x86_107685.nasl", "solaris8_110615.nasl", "solaris8_x86_110616.nasl", "solaris9_113575.nasl", "solaris9_x86_114137.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

if ( get_kb_item("BID-6991") ) exit(0);


port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

# MA 2008-08-18 FP on banner:
# Sendmail @(#)Sendmail version 8.13.3 - Revision 2.006 - 15 November 2007/8.7.1; Mon, 17 Aug 2009 17:33:23 -0700 (MST)
if(banner)
{
  # Digital Defense came up with this nice regex :
  if(egrep(pattern:"Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(/|UCB| )([5-7]\.|[^/]8\.([0-9](\.|;|$)|10\.|11\.[0-6]|12\.[0-7](\/| |\.|\+)))).*", string:banner, icase:TRUE))
		security_hole(port);

  # Since the regex above is VERY complicated, I also include this simpler one, in case the first misses
  # something.
  else if(egrep(pattern:"Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-6]|8\.12\.[0-7]|SMI-8\.([0-9]|1[0-2]))/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
