#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10278);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-1999-0204");
 script_bugtraq_id(2311);
 script_osvdb_id(219);

 script_name(english:"Sendmail 8.6.9 IDENT Remote Overflow");
 script_summary(english:"Check sendmail version number");
 
 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to the ident overflow which allows any remote attacker to
execute arbitrary commands as root.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Sendmail.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/02/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc."); 
 script_family(english:"SMTP problems");

 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);

# Note that we don't have any smtpscan signature for those servers
if(banner)
{
 if(egrep(pattern:".*Sendmail ((8\.([0-5]\..*|6\.[0-9][^0-9])[^0-9])|SMI-([0-7]|8\.[0-6])).*",
	string:banner))
 	security_hole(port);
}
