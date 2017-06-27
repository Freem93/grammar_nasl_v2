#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14296);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2004-0017");
 script_bugtraq_id(9386);
 script_osvdb_id(2691, 6857);

 script_name(english:"phpGroupWare Multiple Module SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is prone to multiple SQL injections." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, a multi-user 
groupware suite written in PHP.

It has been reported that this version may be prone to multiple SQL 
injection vulnerabilities in the 'calendar' and 'infolog' modules. 

The problems exist due to insufficient sanitization of user-supplied 
data. 

A remote attacker may exploit these issues to influence SQL query logic
to disclose sensitive information that could be used to gain 
unauthorized access." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.14.007 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/21");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
script_end_attributes();

 
 script_summary(english:"Checks for PhpGroupWare version");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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

if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-6][^0-9]))", string:matches[1]) )
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

