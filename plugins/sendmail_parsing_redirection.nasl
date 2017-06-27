#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting, solution enhance (9/16/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)

include("compat.inc");

if (description)
{
 script_id(11352);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-1999-0393");
 script_bugtraq_id(8674);
 script_osvdb_id(9310);

 script_name(english:"Sendmail < 8.9.3 Header Prescan Function Message Header DoS");
 script_summary(english:"Checks the version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, allows
remote attackers cause a denial of service by sending messages with a
large number of headers.");
 script_set_attribute(attribute:"solution", value:"Install sendmail 8.9.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Xue Yong Zhi");
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
 #looking for Sendmail 8.8.*, 8.9.2
 if(egrep(pattern:".*sendmail[^0-9]*((8\.(8|8\.[0-9]+|9\.2))|SMI-8\.)/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
