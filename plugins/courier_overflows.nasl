#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12102);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-0224");
 script_bugtraq_id(9845);
 script_osvdb_id(4194, 6927);
 
 script_name(english:"Courier < 0.45 Multiple Remote Overflows");
 script_summary(english:"Checks the version number"); 
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(attribute:"description", value:
"According to its version number, the version of Courier MTA running
on the remote host has multiple buffer overflow vulnerabilities.  A
remote attacker could exploit this to crash the service, or possibly
execute arbitrary code." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Courier 0.45 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/11");
 script_cvs_date("$Date: 2011/03/11 20:59:03 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);

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
 if ( egrep(pattern:"220.*Courier 0\.([0-9]\.|[0-3][0-9]\.|4[0-4]\.)", string:banner) ) { security_hole(port); exit(0); }

}
