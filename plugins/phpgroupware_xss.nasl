#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14708);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2004-0875");
 script_bugtraq_id(11130);
 script_osvdb_id(9729);

 script_name(english:"phpGroupWare Wiki Module XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, a multi-user 
groupware suite written in PHP.

This issue exists due to a lack of sanitization of user-supplied data.
A malicious attacker can exploit a flaw to conduct cross-site 
scripting attacks." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16.003 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  # http://web.archive.org/web/20110226041720/http://phpgroupware.org/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?081a9a2c" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/06");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
script_end_attributes();

 
 script_summary(english:"Checks for PhpGroupWare version");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

matches = eregmatch(pattern:"(.*) under (.*)", string:matches[0]);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0*[0-2]([^0-9]|$)))", string:matches[1]))
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

