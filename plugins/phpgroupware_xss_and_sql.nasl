#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15983);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2004-1383", "CVE-2004-1384", "CVE-2004-1385");
 script_bugtraq_id(11952);
 script_osvdb_id(
   12390, 
   12391, 
   12392, 
   12393, 
   12394, 
   12395, 
   12396
 );

 script_name(english:"phpGroupWare <= 0.9.16.003 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, a multi-user
groupware suite written in PHP. 

The remote version of this software is vulnerable to multiple issues :

  - A cross-site scripting issue may allow an attacker to 
    steal the credentials of third-party users of the remote 
    host. (CVE-2004-1384)

  - A SQL injection vulnerability may allow an attacker to 
    execute arbitrary SQL statements against the remote 
    database. (CVE-2004-1383)
  
  - An information disclosure vulnerability exists that
    is triggered when a specially crafted URL request is
    sent to the 'index.php' script. (CVE-2004-1385)" );
 script_set_attribute(attribute:"solution", value:
"Update to the newest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/14");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
script_end_attributes();

 
 script_summary(english:"Checks the version of phpGroupWare");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8][^0-9]|9\.([0-9][^0-9]|1([0-5][^0-9]|6\.(00[0-3]|RC[0-9]))))", string:matches[1]))
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
