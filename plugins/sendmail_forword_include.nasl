#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/23/09)
# - Grammar fix in the solution (03/05/14)

include("compat.inc");

if (description)
{
 script_id(11349);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2014/03/05 23:13:28 $");

 script_cve_id("CVE-1999-0129");
 script_bugtraq_id(715);
 script_osvdb_id(1113);

 script_name(english:"Sendmail < 8.8.4 Group Write File Hardlink Privilege Escalation");
 script_summary(english:"Checks the version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by local
privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, allows
local users to write to a file and gain group permissions via a
.forward or :include: file.");
 script_set_attribute(attribute:"solution", value:
"Install sendmail newer than 8.8.4 or install a vendor-supplied
patch.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1996/12/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Xue Yong Zhi");
 script_family(english:"SMTP problems");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner)
{
 #looking for Sendmail 8.8, 8.8.1-8.8.3
 if(egrep(pattern:".*sendmail[^0-9]*8\.(8|8\.[1-3])/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
