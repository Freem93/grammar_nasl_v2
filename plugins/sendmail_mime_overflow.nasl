#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10588);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-1999-0206");
 script_osvdb_id(485);
 
 script_name(english:"Sendmail mime7to8() Function Remote Overflow");
 script_summary(english:"Checks sendmail version number");
 
 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to a MIME buffer overflow attack which allows anyone to
execute arbitrary commands as root.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Sendmail.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
	
 script_set_attribute(attribute:"vuln_publication_date", value:"1996/10/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/01/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2012 Tenable Network Security, Inc."); 
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

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:"Sendmail.*[^/]8\.8\.[01]/.*", string:banner))
 	security_hole(port);
}
