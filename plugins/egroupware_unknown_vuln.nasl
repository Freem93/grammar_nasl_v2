#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15719);

 script_cve_id("CVE-2005-1129", "CVE-2005-1202", "CVE-2005-1203");
 script_bugtraq_id(11625, 13137, 13212);
 script_osvdb_id(15499, 15649, 15750, 15751, 15752, 15753);

 script_version("$Revision: 1.20 $");
 
 script_name(english:"EGroupWare Multiple Vulnerabilities (SQLi, ID)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running eGroupWare, a web-based groupware solution. 

It is reported that versions 1.0.0.006 and older are prone to multiple
SQL injection and cross-site scripting flaws." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00069-04202005" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=320768" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to eGroupWare 1.0.0.007 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/12");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Checks for the version of EGroupWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("egroupware_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
kb   = get_kb_item("www/" + port + "/egroupware");
if ( ! kb ) exit(0);

stuff = eregmatch( pattern:"(.*) under (.*)", string:kb );
version = stuff[1];
if(ereg(pattern:"^(0\.|1\.0\.0(\.00[0-6]|[^0-9\.]))", string:version) )
{
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
}
