#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19754);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-2761");
 script_bugtraq_id(14724);
 script_osvdb_id(18979);

 script_name(english:"phpGroupWare Main Screen Message Body XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, a multi-user 
groupware suite written in PHP.

This version is vulnerable to script injection, whereby a malicious 
admin can inject script code into the main screen message." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16.007 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
script_end_attributes();

 
 script_summary(english:"Checks for PhpGroupWare version");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0[0-6]([^0-9]|$)))", string:matches[1]))
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
