#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15711);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id("CVE-2001-0043");
 script_bugtraq_id(2069);
 script_osvdb_id(1682);
	
 script_name(english:"phpGroupWare phpgw.inc.php phpgw_info Parameter Remote File Inclusion");
 script_summary(english:"Checks for PhpGroupWare version");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of PhpGroupWare hosted on the remote web server has a
vulnerability that may permit remote attackers to execute arbitrary
commands through the 'phpgw_info' parameter of the 'phpgw.inc.php'
script, resulting in a loss of integrity." );
 script_set_attribute(attribute:"solution", value:
"Update to phpGroupWare version 0.9.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
 script_end_attributes();
 
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

if ( ereg(pattern:"^0\.([0-8]\.|9\.[0-6][^0-9])", string:matches[1]) ) 
	security_hole(port);
