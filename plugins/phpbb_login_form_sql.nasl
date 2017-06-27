#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15780);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2004-1315");
 script_bugtraq_id(11716);
 script_osvdb_id(11719, 11961, 11962);
 script_xref(name:"CERT", value:"497400");
 script_xref(name:"EDB-ID", value:"647");
 
 script_name(english:"phpBB viewtopic.php highlight Parameter SQL Injection (ESMARKCONANT)");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpBB. There is a flaw in the remote
software that could allow anyone to inject arbitrary SQL commands in
the login form. An attacker could exploit this flaw to bypass the
authentication of the remote host or execute arbitrary SQL statements
against the remote database.

ESMARKCONANT is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'phpBB viewtopic.php Arbitrary Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/12");
 script_cvs_date("$Date: 2017/04/19 13:27:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_summary(english:"SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];

if ( ereg(pattern:"^([01]\.|2\.0\.([0-9]|10)([^0-9]|$))", string:version ) )
{
	security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

