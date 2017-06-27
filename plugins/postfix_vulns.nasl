#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11820);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id("CVE-2003-0468", "CVE-2003-0540");
 script_bugtraq_id(8361, 8362);
 script_osvdb_id(6551, 10544, 10545);
 script_xref(name:"RHSA", value:"2003:251-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:033");
 
 script_name(english:"Postfix < 2.0 Multiple Vulnerabilities");
 script_summary(english: "Checks the version of the remote Postfix daemon");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Postfix that is as old as or 
older than 1.1.12.

There are two vulnerabilities in this version that could allow an 
attacker to remotely disable it, or to be used as a DDoS agent against 
arbitrary hosts.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Postfix 2.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/08/15");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postfix:postfix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");
 script_dependencie("smtpscan.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if ( report_paranoia < 2 )
 banner = get_kb_item("smtp/" + port + "/banner");
else
 banner = get_kb_item("smtp/" + port + "/real_banner");

if(!banner)exit(0);

if(ereg(pattern:".*Postfix 1\.(0\..*|1\.([0-9][^0-9]|1[0-2]))", string:banner)||
   ereg(pattern:".*Postfix 2001.*", string:banner))
{
 security_warning(port);
}
