#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - Fixed typo in the solution (03/05/2014)

include("compat.inc");

if (description)
{
 script_id(11350);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/03/05 23:17:30 $");

 script_cve_id("CVE-1999-1109");
 script_bugtraq_id(904);
 script_osvdb_id(1182);

 script_name(english:"Sendmail Crafted ETRN Commands Remote DoS");
 script_summary(english:"Checks the version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number,
allows remote attackers to cause a denial of service by
sending a series of ETRN commands then disconnecting from
the server, while Sendmail continues to process the commands
after the connection has been terminated.");
 script_set_attribute(attribute:"solution", value:
"Install sendmail version 8.10.1 and higher, or install a 
vendor-supplied patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/12/22");
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
 #looking for Sendmail 8.10.0 and previous
 if(egrep(pattern:".*sendmail[^0-9]*(SMI-)?8\.([0-9]|[0-9]\.[0-9]+|10\.0)/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
